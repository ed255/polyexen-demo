#![feature(box_patterns)]

use num_bigint::{BigInt, BigUint};
use num_traits::Zero;
use polyexen::{
    analyze::{
        bound_base, find_bounds_poly, solve_ranged_linear_comb, to_biguint, Analysis, Attrs, Bound,
    },
    expr::{Column, ColumnKind, ColumnQuery, Expr, ExprDisplay, PlonkVar as Var},
    halo2_proofs::halo2curves::bn256::Fr,
    plaf::{
        frontends::halo2::{gen_witness, get_plaf},
        AliasMap, Cell, CellDisplay, Lookup, Plaf, Poly, Witness,
    },
};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{
    self,
    cell::RefCell,
    collections::{HashMap, HashSet},
    env, fmt,
    fs::File,
    io::{self, BufRead, BufReader},
    str::FromStr,
};
/*
use zkevm_circuits::{
    bytecode_circuit::circuit::BytecodeCircuit,
    copy_circuit::CopyCircuit,
    // evm_circuit::util::math_gadget::add_words::tests::AddWordsTestContainer,
    // evm_circuit::util::math_gadget::test_util::UnitTestMathGadgetBaseCircuit,
    // copy_circuit::CopyCircuit,
    // evm_circuit::EvmCircuit,
    // exp_circuit::ExpCircuit,
    // keccak_circuit::KeccakCircuit,
    // pi_circuit::PiTestCircuit as PiCircuit,
    // state_circuit::StateCircuit,
    // super_circuit::SuperCircuit,
    // tx_circuit::TxCircuit,
    util::SubCircuit,
};
*/
// use zkevm_hashes::sha256::vanilla::tests::Sha256BitCircuit;
// use axiom_core::tests::integration::eth_block_header_test_circuit;
// use axiom_query::{
//     components::results::tests::results_root_test_circuit,
//     subquery_aggregation::tests::subquery_agg_test_circuit,
//     verify_compute::tests::test_verify_no_compute_circuit,
// };
use axiom_client::tests::keccak::all_subquery_test_circuit;
use axiom_query::{
    components::results::tests::results_root_test_circuit,
    verify_compute::tests::{
        aggregation::verify_compute_agg_test_circuit, verify_compute_test_circuit,
        verify_no_compute_test_circuit,
    },
};

const N_ROWS: usize = 0x50;

// use demo::utils::{gen_empty_block, name_challanges};
use demo::utils::name_challanges;

#[derive(Debug, Clone, Copy)]
struct PolyRef {
    /// Row offset
    offset: usize,
    /// Index in Plaf.polys
    index: usize,
}

#[derive(Debug, Clone, Copy)]
struct LookupSrcRef {
    /// Row offset
    offset: usize,
    /// Index in Plaf.lookups
    index: usize,
    /// Expr Index
    expr_index: usize,
}

#[derive(Debug, Clone, Copy)]
struct LookupDstRef {
    /// Row offset
    offset: usize,
    /// Index in Plaf.lookups
    index: usize,
    /// Expr Index
    expr_index: usize,
}

impl LookupSrcRef {
    fn get<'a>(&self, plaf: &'a Plaf) -> (usize, &'a Expr<Var>) {
        (
            self.offset,
            &plaf.lookups[self.index].exps.0[self.expr_index],
        )
    }
}

impl LookupDstRef {
    fn get<'a>(&self, plaf: &'a Plaf) -> (usize, &'a Expr<Var>) {
        (
            self.offset,
            &plaf.lookups[self.index].exps.1[self.expr_index],
        )
    }
}

impl PolyRef {
    fn get<'a>(&self, plaf: &'a Plaf) -> (usize, &'a Poly) {
        (self.offset, &plaf.polys[self.index])
    }
}

struct Context {
    plaf: Plaf,
    alias_map: AliasMap,
    // Map from Cell to Polynomial identity that uses that cell
    cell_expr_map: HashMap<Cell, Vec<PolyRef>>,
    // Table of Witness Cell to list of copy cells
    cell_copy_table: Vec<Vec<Vec<Cell>>>,
    // Map from Cell to lookup src expression that uses that cell
    cell_lookup_src_map: HashMap<Cell, Vec<LookupSrcRef>>,
    // Map from Cell to lookup dst expression that uses that cell
    cell_lookup_dst_map: HashMap<Cell, Vec<LookupDstRef>>,
    analysis: RefCell<Analysis<Cell>>,
    witness: Witness,
    bound_default: Bound,
    // Cells defined by the user to be inputs to the circuit
    input_set: HashSet<Cell>,
    // Cells defined by the user to be outputs to the circuit
    output_set: HashSet<Cell>,
    // Set of advice cells indexed by column_index, row_offset marked to be ignored.
    mark_set: Vec<Vec<bool>>,
}

impl Context {
    fn new(plaf: Plaf, witness: Option<Witness>) -> Self {
        let p = &plaf.info.p;
        let analysis = Analysis::new();
        let witness = witness.unwrap_or_else(|| plaf.gen_empty_witness());
        let bound_default = bound_base(p);
        let alias_map = plaf.alias_map();
        let mut ctx = Context {
            plaf,
            alias_map,
            cell_expr_map: HashMap::new(),
            cell_copy_table: Vec::new(),
            cell_lookup_src_map: HashMap::new(),
            cell_lookup_dst_map: HashMap::new(),
            analysis: RefCell::new(analysis),
            witness,
            bound_default,
            input_set: HashSet::new(),
            output_set: HashSet::new(),
            mark_set: Vec::new(),
        };
        log::info!("loading mark_set");
        ctx.mark_set = ctx.load_mark_set();
        log::info!("done");
        log::info!("building cell_copy_table");
        ctx.cell_copy_table = ctx.cell_copy_table();
        log::info!("done");
        log::info!("building cell_expr_map");
        ctx.cell_expr_map = ctx.cell_expr_map();
        log::info!("done");
        log::info!("building cell_lookup_src_map");
        ctx.cell_lookup_src_map = ctx.cell_lookup_src_map();
        log::info!("done");
        log::info!("building cell_lookup_dst_map");
        ctx.cell_lookup_dst_map = ctx.cell_lookup_dst_map();
        log::info!("done");
        log::info!("analyze_all");
        ctx.analyze_all();
        log::info!("done");
        ctx
    }

    fn load_mark_set(&self) -> Vec<Vec<bool>> {
        let f = File::open("/tmp/mark_list.txt").unwrap();
        let mut mark_set =
            vec![vec![false; self.plaf.info.num_rows]; self.plaf.columns.witness.len()];
        let mut reader = BufReader::new(f);
        let mut buf = String::new();
        while let Ok(n) = reader.read_line(&mut buf) {
            if n == 0 {
                break;
            }
            let parts = buf.strip_suffix('\n').unwrap().split(",");
            let mut numbers = parts.map(|s| usize::from_str_radix(s, 10).unwrap());
            let column_index = numbers.next().unwrap();
            let row_offset = numbers.next().unwrap();
            mark_set[column_index][row_offset] = true;
            buf.clear();
        }
        mark_set
    }

    fn resolve_wit(&self, index: usize, offset: usize) -> Option<BigUint> {
        if let Some(f) = &self.witness.witness[index][offset] {
            return Some(f.clone());
        }
        if let Some(attrs) = self
            .analysis
            .borrow()
            .vars_attrs
            .get(&Cell::new(Column::new(ColumnKind::Witness, index), offset))
        {
            if let Some(f) = attrs.bound.unique() {
                return Some(f.clone());
            }
        }
        return None;
    }

    fn resolve_var<const WITNESS: bool>(&self, v: &Var, offset: usize) -> Expr<Cell> {
        match v {
            Var::Query(ColumnQuery { column, rotation }) => {
                let offset =
                    (offset as i32 + rotation).rem_euclid(self.plaf.info.num_rows as i32) as usize;
                match column.kind {
                    ColumnKind::Fixed => Expr::Const(to_biguint(
                        self.plaf.fixed[column.index()][offset]
                            .clone()
                            .unwrap_or_else(BigInt::zero),
                        &self.plaf.info.p,
                    )),
                    ColumnKind::Witness => {
                        if WITNESS {
                            if let Some(f) = self.resolve_wit(column.index(), offset) {
                                Expr::Const(f.clone())
                            } else {
                                Expr::Var(Cell::new(*column, offset))
                            }
                        } else {
                            Expr::Var(Cell::new(*column, offset))
                        }
                    }
                    _ => Expr::Var(Cell::new(*column, offset)),
                }
            }
            Var::Challenge { index: _, phase: _ } => {
                // TODO: Figure out something better :P
                Expr::Const(BigUint::from(1234u64))
            }
        }
    }

    fn cell_expr_map(&self) -> HashMap<Cell, Vec<PolyRef>> {
        let mut map = HashMap::new();
        for offset in 0..self.plaf.info.num_rows {
            for (index, poly) in self.plaf.polys.iter().enumerate() {
                let exp = self.eval_partial::<false>(&poly.exp, offset);
                let vars = exp.vars();
                let poly_ref = PolyRef { offset, index };
                for var in vars {
                    map.entry(var)
                        .and_modify(|ps: &mut Vec<PolyRef>| ps.push(poly_ref))
                        .or_insert(vec![poly_ref]);
                }
            }
        }
        map
    }

    fn cell_copy_table(&self) -> Vec<Vec<Vec<Cell>>> {
        let mut table =
            vec![vec![Vec::new(); self.plaf.info.num_rows]; self.plaf.columns.witness.len()];
        for copy in &self.plaf.copys {
            let (column_a, column_b) = copy.columns;
            for (offset_a, offset_b) in &copy.offsets {
                if matches!(column_a.kind, ColumnKind::Witness) {
                    table[column_a.index()][*offset_a].push(Cell::new(column_b, *offset_b));
                }
                if matches!(column_b.kind, ColumnKind::Witness) {
                    table[column_b.index()][*offset_b].push(Cell::new(column_a, *offset_a));
                }
            }
        }
        // println!("DBG copy at w00[1806] = {:?}", table[0][1806]);
        table
    }

    fn cell_lookup_src_map(&self) -> HashMap<Cell, Vec<LookupSrcRef>> {
        let mut map = HashMap::new();
        for offset in 0..self.plaf.info.num_rows {
            for (index, lookup) in self.plaf.lookups.iter().enumerate() {
                for (expr_index, expr) in lookup.exps.0.iter().enumerate() {
                    let exp = self.eval_partial::<false>(&expr, offset);
                    let vars = exp.vars();
                    let lookup_ref = LookupSrcRef {
                        offset,
                        index,
                        expr_index,
                    };
                    for var in vars {
                        map.entry(var)
                            .and_modify(|ps: &mut Vec<LookupSrcRef>| ps.push(lookup_ref))
                            .or_insert(vec![lookup_ref]);
                    }
                }
            }
        }
        map
    }

    fn cell_lookup_dst_map(&self) -> HashMap<Cell, Vec<LookupDstRef>> {
        let mut map = HashMap::new();
        for offset in 0..self.plaf.info.num_rows {
            for (index, lookup) in self.plaf.lookups.iter().enumerate() {
                for (expr_index, expr) in lookup.exps.1.iter().enumerate() {
                    let exp = self.eval_partial::<false>(&expr, offset);
                    let vars = exp.vars();
                    let lookup_ref = LookupDstRef {
                        offset,
                        index,
                        expr_index,
                    };
                    for var in vars {
                        map.entry(var)
                            .and_modify(|ps: &mut Vec<LookupDstRef>| ps.push(lookup_ref))
                            .or_insert(vec![lookup_ref]);
                    }
                }
            }
        }
        map
    }

    fn eval_partial<const WITNESS: bool>(&self, exp: &Expr<Var>, offset: usize) -> Expr<Cell> {
        let p = &self.plaf.info.p;
        let mut exp =
            self.plaf
                .eval_partial(exp, &|v, o| self.resolve_var::<WITNESS>(v, o), offset);
        exp.simplify(p);
        exp
    }

    fn analyze_poly(&self, offset: usize, poly: &Poly) -> HashSet<Cell> {
        let p = &self.plaf.info.p;
        let mut exp = self.eval_partial::<true>(&poly.exp, offset);
        if exp.is_zero() {
            return HashSet::new();
        }
        if matches!(exp, Expr::Const(_)) || matches!(exp, Expr::Neg(box Expr::Const(_))) {
            println!(
                "WARNING: Poly constraint not satisfied at offset {}: \"{}\":\n  {}",
                offset,
                poly.name,
                self.disp_expr_cell(&exp)
            );
        }
        let update1 = find_bounds_poly(&exp, p, &mut *self.analysis.borrow_mut());
        let update2 = solve_ranged_linear_comb(&exp, p, &mut *self.analysis.borrow_mut());
        exp.normalize(p);
        let update3 = find_bounds_poly(&exp, p, &mut *self.analysis.borrow_mut());
        update1
            .iter()
            .chain(update2.iter())
            .chain(update3.iter())
            .cloned()
            .collect()
    }

    fn analyze(&mut self, mut set: HashSet<Cell>) {
        while set.len() != 0 {
            // println!("DBG Analyze set {:?}", set);
            let mut new_set = HashSet::new();
            for cell in &set {
                if let Some(poly_refs) = self.cell_expr_map.get(cell) {
                    for poly_ref in poly_refs {
                        let (offset, poly) = poly_ref.get(&self.plaf);
                        // println!("DBG analyze poly {}", poly.exp);
                        new_set.extend(self.analyze_poly(offset, poly).into_iter());
                    }
                }
            }
            // println!("DBG3 {}", self.analysis.borrow().vars_attrs.len());
            set = new_set;
        }
    }

    fn analyze_lookups(&self, lookup: &Lookup) {
        // Only analyze lookups to fixed columns
        let num_rows = self.plaf.info.num_rows;
        let num_exps = lookup.exps.1.len();
        let mut dst_table = vec![vec![BigUint::zero(); num_rows]; num_exps];
        for offset in 0..num_rows {
            for (exp_index, exp) in lookup
                .exps
                .1
                .iter()
                .map(|e| self.eval_partial::<true>(e, offset))
                .enumerate()
            {
                if let Expr::Const(f) = exp {
                    dst_table[exp_index][offset] = f.clone();
                } else {
                    return;
                }
            }
        }
        for offset in 0..num_rows {
            let mut match_rows = vec![true; num_rows];
            for (exp_index, exp) in lookup
                .exps
                .0
                .iter()
                .map(|e| self.eval_partial::<true>(e, offset))
                .enumerate()
            {
                let mut col_match_rows = vec![false; num_rows];
                if let Some(src_bound) = self.analysis.borrow().bound_exp(&exp) {
                    for dst_offset in 0..num_rows {
                        if src_bound
                            .overlap(&Bound::new_unique(dst_table[exp_index][dst_offset].clone()))
                        {
                            col_match_rows[dst_offset] = true;
                        }
                    }
                } else {
                    return;
                }
                for (match_row, col_match_row) in match_rows.iter_mut().zip(col_match_rows) {
                    *match_row &= col_match_row;
                }
            }
            let match_rows: Vec<usize> = match_rows
                .iter()
                .enumerate()
                .filter_map(|(row, matches)| if *matches { Some(row) } else { None })
                .collect();
            for exp_index in 0..num_exps {
                let exp_bound = Bound::new(
                    match_rows
                        .iter()
                        .map(|row| dst_table[exp_index][*row].clone()),
                );
                if let Expr::Var(cell) =
                    self.eval_partial::<true>(&lookup.exps.0[exp_index], offset)
                {
                    self.analysis
                        .borrow_mut()
                        .vars_attrs
                        .insert(cell, Attrs { bound: exp_bound });
                }
            }
        }
    }

    fn analyze_all(&mut self) {
        for offset in 0..self.plaf.info.num_rows {
            for poly in &self.plaf.polys {
                self.analyze_poly(offset, &poly);
            }
        }
        for lookup in &self.plaf.lookups {
            self.analyze_lookups(lookup);
        }
        self.analyze_copys();
        // println!("DBG2 {}", self.analysis.borrow().vars_attrs.len());
    }

    fn analyze_copys(&mut self) {
        for (column_index, column) in self.cell_copy_table.iter().enumerate() {
            for (offset, row) in column.iter().enumerate() {
                let cell = Cell::new(Column::new(ColumnKind::Witness, column_index), offset);
                for copy in row {
                    if matches!(copy.column.kind, ColumnKind::Fixed) {
                        let value = self.plaf.fixed[copy.column.index()][copy.offset()]
                            .clone()
                            .unwrap_or_else(|| BigInt::zero());
                        self.analysis.borrow_mut().vars_attrs.insert(
                            cell,
                            Attrs {
                                bound: Bound::new_unique(to_biguint(value, &self.plaf.info.p)),
                            },
                        );
                    }
                }
            }
        }
    }

    fn cell_fmt(&self, f: &mut fmt::Formatter<'_>, c: &Cell) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            CellDisplay {
                c,
                plaf: &self.plaf
            }
        )
    }

    fn disp_expr_cell<'a>(
        &'a self,
        exp: &'a Expr<Cell>,
    ) -> ExprDisplay<Cell, impl Fn(&mut fmt::Formatter, &Cell) -> Result<(), fmt::Error> + 'a> {
        ExprDisplay {
            e: &exp,
            var_fmt: |f, v| self.cell_fmt(f, &v),
        }
    }

    fn disp_expr_plonk<'a>(
        &'a self,
        exp: &'a Expr<Var>,
    ) -> ExprDisplay<Var, impl Fn(&mut fmt::Formatter, &Var) -> Result<(), fmt::Error> + 'a> {
        ExprDisplay {
            e: &exp,
            var_fmt: |f, v| self.plaf.fmt_var(f, &v),
        }
    }
}

fn alias_replace(plaf: &mut Plaf) {
    for aliases in plaf
        .columns
        .fixed
        .iter_mut()
        .map(|c| &mut c.aliases)
        .chain(plaf.columns.public.iter_mut().map(|c| &mut c.aliases))
        .chain(plaf.columns.witness.iter_mut().map(|c| &mut c.aliases))
    {
        for alias in aliases.iter_mut() {
            // Bytecode
            // *alias = alias.replace("BYTECODE_", "");

            // Exp
            // *alias = alias.replace("EXP_", "");
            // *alias = alias.replace("GADGET_MUL_ADD", "MulAdd");
            // *alias = alias.replace("_col", "_c");
            // *alias = alias.replace("identifier", "id");
            // *alias = alias.replace("parity_check", "parChe");
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // let k: u32 = 8;
    // Empty input
    // let (k, circuit) = verify_no_compute_test_circuit();
    // let (k, circuit) = verify_compute_test_circuit();
    // let (k, circuit) = verify_compute_agg_test_circuit();
    // let (k, _, circuit) = results_root_test_circuit();
    let (k, circuit) = all_subquery_test_circuit();
    // let sample = eth_block_header_test_circuit("leaf");
    // let k = sample.k;
    // let circuit = sample.leaf.unwrap();
    // let sample = eth_block_header_test_circuit("inter");
    // let k = sample.k;
    // let circuit = sample.inter.unwrap().0;
    // let sample = eth_block_header_test_circuit("root");
    // let k = sample.k;
    // let circuit = sample.root.unwrap();

    // let (k, instances, circuit) = subquery_agg_test_circuit();
    // let block = gen_empty_block();
    // let circuit = BytecodeCircuit::<Fr>::new_from_block(&block);
    // let circuit = ExpCircuit::<Fr>::new_from_block(&block);
    // let k: u32 = 12;
    // use eth_types::Word;
    // let witnesses: Vec<Word> = vec![Word::from(0), Word::from(0), Word::from(0)];
    // let circuit = UnitTestMathGadgetBaseCircuit::<AddWordsTestContainer<Fr, 2, 0u64, true>>::new(
    //     k as usize, witnesses,
    // );
    // let block = gen_empty_block();
    // let circuit = CopyCircuit::<Fr>::new_from_block(&block);
    // let k: u32 = 10;
    let mut plaf = get_plaf(k, &circuit).unwrap();
    alias_replace(&mut plaf);
    plaf.simplify();
    name_challanges(&mut plaf);
    // let witness = Some(gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], vec![]).unwrap());
    let witness = None;
    let mut ctx = Context::new(plaf, witness);
    // ctx.analyze();
    // for (cell, attrs) in &analysis.vars_attrs {
    //     if attrs.bound == bound_base {
    //         continue;
    //     }
    //     println!(
    //         "{}",
    //         CellDisplay {
    //             c: cell,
    //             plaf: &plaf
    //         }
    //     );
    //     println!("  {:?}", attrs.bound);
    // }
    let mut rl = DefaultEditor::new().unwrap();
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }

    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let filename = &args[1];
        let file = File::open(filename).unwrap();
        println!("Processing input file {}", filename);
        for line in io::BufReader::new(file).lines() {
            let line = line.unwrap();
            let line_str = line.as_str();
            println!("> {}", line_str);
            run(&mut ctx, line_str);
        }
    }

    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str()).unwrap();
                run(&mut ctx, line.as_str());
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    rl.save_history("history.txt").unwrap();
}

/// Helper type to print formatted tables in MarkDown
pub(crate) struct DisplayTable {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl DisplayTable {
    pub(crate) fn new(header: Vec<String>) -> Self {
        Self {
            header,
            rows: Vec::new(),
        }
    }
    fn push_row(&mut self, row: Vec<String>) {
        assert_eq!(self.header.len(), row.len());
        self.rows.push(row)
    }
    fn print_row(row: &Vec<String>, rows_width: &[usize]) {
        for (i, h) in row.iter().enumerate() {
            // if i == 0 {
            //     print!("|");
            // }
            print!("{:width$} ", h, width = rows_width[i]);
        }
        println!();
    }
    pub(crate) fn print(&self) {
        let mut rows_width = vec![0; self.header.len()];
        for row in std::iter::once(&self.header).chain(self.rows.iter()) {
            for (i, s) in row.iter().enumerate() {
                if s.len() > rows_width[i] {
                    rows_width[i] = s.len();
                }
            }
        }
        Self::print_row(&self.header, &rows_width);
        for (i, width) in rows_width.iter().enumerate() {
            // if i == 0 {
            //     print!("|");
            // }
            print!("{:-<width$} ", "", width = width);
        }
        println!();
        for row in &self.rows {
            Self::print_row(row, &rows_width);
        }
    }
}

fn print_lookups(ctx: &Context, offset_str: &str) {
    let offset = usize::from_str_radix(offset_str, 10).unwrap();
    let p = &ctx.plaf.info.p;

    for lookup in &ctx.plaf.lookups {
        println!("\"{}\"", lookup.name);
        print!("ori0 src: {{");
        for (i, exp) in lookup.exps.0.iter().enumerate() {
            if i != 0 {
                print!(", ");
            }
            print!("{}", ctx.disp_expr_plonk(exp));
        }
        println!("}}");
        print!("ori0 dst: {{");
        for (i, exp) in lookup.exps.1.iter().enumerate() {
            if i != 0 {
                print!(", ");
            }
            print!("{}", ctx.disp_expr_plonk(exp));
        }
        println!("}}");
    }
}

fn print_polys(ctx: &Context, offset_str: &str) {
    let offset = usize::from_str_radix(offset_str, 10).unwrap();
    let p = &ctx.plaf.info.p;
    let mut query_names: HashMap<ColumnQuery, String> = HashMap::new();
    for (selector, map) in &ctx.plaf.metadata.query_names {
        let s = ctx.eval_partial::<true>(selector, offset);
        if s.is_const_not_zero() {
            query_names.extend(map.clone().into_iter());
        }
    }
    let skip_patterns = [
        "w bit boolean",
        "a bit boolean",
        "e bit boolean",
        "is_padding boolean",
    ];
    for poly in &ctx.plaf.polys {
        if skip_patterns
            .iter()
            .any(|skip_pattern| poly.name.contains(skip_pattern))
        {
            continue;
        }
        let exp = ctx.eval_partial::<true>(&poly.exp, offset);
        if exp.is_zero() {
            continue;
        }
        // exp.normalize(p);
        println!("\"{}\"", poly.name);
        // println!(
        //     "  ori0: {}",
        //     ctx.disp_expr_cell(&exp)
        // );
        println!(
            "  ori1: {}",
            ExprDisplay {
                e: &poly.exp,
                var_fmt: |f, v| {
                    if let Var::Query(q) = v {
                        if let Some(name) = query_names.get(&q) {
                            write!(f, "{}", name)?;
                            return Ok(());
                        }
                    }
                    ctx.plaf.fmt_var(f, &v)
                }
            }
        );
        // println!(
        //     "  res0: {}",
        //     ctx.disp_expr_cell(&exp)
        // );
        println!(
            "  res1: {}",
            ExprDisplay {
                e: &exp,
                var_fmt: |f, v| {
                    let q = ColumnQuery {
                        column: v.column,
                        rotation: v.offset as i32 - offset as i32,
                    };
                    if let Some(name) = query_names.get(&q) {
                        write!(f, "{}", name)?;
                        return Ok(());
                    }
                    ctx.cell_fmt(f, &v)
                }
            }
        );
    }
}

fn print_table(ctx: &Context, offset_str: &str) {
    let offset = usize::from_str_radix(offset_str, 10).unwrap();
    let mut column_names = Vec::new();
    column_names.push("#".to_string());
    let skip_pattern = ".b";
    let mut skip_witnes_indexes = Vec::new();
    for column in &ctx.plaf.columns.fixed {
        column_names.push(column.name().clone());
    }
    for column in &ctx.plaf.columns.public {
        column_names.push(column.name().clone());
    }
    for (i, column) in ctx.plaf.columns.witness.iter().enumerate() {
        if column.name().contains(skip_pattern) {
            skip_witnes_indexes.push(i);
            continue;
        }
        column_names.push(column.name().clone());
    }
    let mut table = DisplayTable::new(column_names.into());
    // Query names in matrix [column_index][row]
    let mut query_names_fixed = vec![vec![String::new(); N_ROWS]; ctx.plaf.columns.fixed.len()];
    let mut query_names_witness = vec![vec![String::new(); N_ROWS]; ctx.plaf.columns.witness.len()];
    for row in offset.saturating_sub(N_ROWS)..offset + N_ROWS {
        for (selector, map) in &ctx.plaf.metadata.query_names {
            let s = ctx.eval_partial::<true>(selector, row);
            if s.is_const_not_zero() {
                for (q, name) in map.iter() {
                    let ColumnQuery { column, rotation } = q;
                    let abs_offset = (row as i32 + rotation)
                        .rem_euclid(ctx.plaf.info.num_rows as i32)
                        - offset as i32;
                    if abs_offset < 0 || abs_offset >= N_ROWS as i32 {
                        continue;
                    }
                    let abs_offset = abs_offset as usize;
                    let query_name: &mut String = match column.kind {
                        ColumnKind::Fixed => &mut query_names_fixed[column.index()][abs_offset],
                        ColumnKind::Witness => &mut query_names_witness[column.index()][abs_offset],
                        _ => unimplemented!(),
                    };
                    if query_name.len() == 0 {
                        *query_name = format!("{}", name);
                    } else {
                        *query_name = format!("{},{}", query_name, name);
                    }
                }
            }
        }
    }
    for row in offset..offset + N_ROWS {
        if row >= ctx.plaf.info.num_rows {
            continue;
        }
        let mut row_names = Vec::new();
        row_names.push(String::new());
        for index in 0..ctx.plaf.columns.fixed.len() {
            row_names.push(query_names_fixed[index][row - offset].clone());
        }
        for index in 0..ctx.plaf.columns.witness.len() {
            if skip_witnes_indexes.contains(&index) {
                continue;
            }
            row_names.push(query_names_witness[index][row - offset].clone());
        }
        table.push_row(row_names);

        let mut row_values = Vec::new();
        row_values.push(Some(format!("{}", row)));
        for index in 0..ctx.plaf.columns.fixed.len() {
            row_values.push(Some(
                ctx.plaf.fixed[index][row]
                    .clone()
                    .map(|v| format!("{:x}", v))
                    .unwrap_or_else(|| format!("0")),
            ));
        }
        for index in 0..ctx.plaf.columns.public.len() {
            // TODO
            row_values.push(
                ctx.plaf.fixed[index][row]
                    .clone()
                    .map(|v| format!("{:x}", v)),
            );
        }
        for index in 0..ctx.plaf.columns.witness.len() {
            if skip_witnes_indexes.contains(&index) {
                continue;
            }
            if let Some(f) = &ctx.witness.witness[index][row] {
                row_values.push(Some(format!("{:x}", f)));
                continue;
            }
            if let Some(attrs) = ctx
                .analysis
                .borrow()
                .vars_attrs
                .get(&Cell::new(Column::new(ColumnKind::Witness, index), row))
            {
                if attrs.bound != ctx.bound_default {
                    row_values.push(Some(format!("{}", attrs.bound)));
                    continue;
                }
            }
            row_values.push(
                ctx.witness.witness[index][row]
                    .clone()
                    .map(|v| format!("{:x}", v)),
            );
        }
        table.push_row(
            row_values
                .into_iter()
                .map(|o| o.map(|x| format!("{}", x)).unwrap_or_else(|| format!("?")))
                .collect(),
        );
    }
    table.print();
}

fn get_cell_from_str(ctx: &Context, cell_str: &str) -> Option<Cell> {
    let (name_str, offset_str) = cell_str
        .split_once('[')
        .map(|(name, offset)| (name, &offset[..offset.len() - 1]))
        .unwrap();
    if let Some(var) = ctx.alias_map.0.get(name_str) {
        let offset = usize::from_str_radix(offset_str, 10).unwrap();
        match var {
            Var::Query(ColumnQuery {
                column,
                rotation: _,
            }) => {
                return Some(Cell::new(column.clone(), offset));
            }
            _ => unreachable!(),
        }
    } else {
        println!("Error: column \"{}\" not found", name_str);
        return None;
    }
}

fn set_witness(ctx: &mut Context, cell_str: &str, val_str: &str) {
    let val = if val_str == "?" {
        None
    } else {
        // Some(u64::from_str_radix(val_str, 10).unwrap())
        Some(BigUint::from_str(val_str).unwrap())
    };
    if let Some(cell) = get_cell_from_str(&ctx, cell_str) {
        match cell.column.kind {
            ColumnKind::Witness => {
                ctx.witness.witness[cell.column.index()][cell.offset()] = val;
                ctx.analyze([cell].into_iter().collect());
            }
            ColumnKind::Public => unimplemented!(),
            _ => unreachable!(),
        }
    }
}

fn set_input(ctx: &mut Context, cell_str: &str) {
    if let Some(cell) = get_cell_from_str(&ctx, cell_str) {
        ctx.input_set.insert(cell);
    }
}

fn set_output(ctx: &mut Context, cell_str: &str) {
    if let Some(cell) = get_cell_from_str(&ctx, cell_str) {
        ctx.output_set.insert(cell);
    }
}

fn unused_rows(ctx: &mut Context, from_str: &str, to_str: &str) {
    let from_offset = usize::from_str(from_str).unwrap();
    let to_offset = usize::from_str(to_str).unwrap();

    println!(
        "# Used cells in inactive rows from {} to {}",
        from_offset, to_offset
    );
    for column_index in 0..ctx.plaf.columns.witness.len() {
        for offset in from_offset..=to_offset {
            let cell = Cell::new(Column::new(ColumnKind::Witness, column_index), offset);
            if let Some(poly_refs) = ctx.cell_expr_map.get(&cell) {
                for poly_ref in poly_refs {
                    let (poly_offset, poly) = poly_ref.get(&ctx.plaf);
                    let exp = ctx.eval_partial::<true>(&poly.exp, poly_offset);
                    // Skip whenever the partial evaluated expression doesn't contain the cell
                    // variable anymore.
                    if !exp.vars().contains(&cell) {
                        continue;
                    }
                    if exp.is_zero() {
                        continue;
                    }
                    println!("\"{}\"\n  {}", poly.name, ctx.disp_expr_cell(&exp));
                }
            }
        }
    }
}

fn cell_used(ctx: &mut Context, cell_str: &str) {
    if let Some(cell) = get_cell_from_str(&ctx, cell_str) {
        if let Some(poly_refs) = ctx.cell_expr_map.get(&cell) {
            for poly_ref in poly_refs {
                let (poly_offset, poly) = poly_ref.get(&ctx.plaf);
                let exp = ctx.eval_partial::<true>(&poly.exp, poly_offset);
                // Skip whenever the partial evaluated expression doesn't contain the cell
                // variable anymore.
                if !exp.vars().contains(&cell) {
                    continue;
                }
                if exp.is_zero() {
                    continue;
                }
                println!("\"{}\"\n  {}", poly.name, ctx.disp_expr_cell(&exp));
            }
        }
    }
}

fn free_cells(ctx: &Context) {
    let skip_patterns = [
        "w bit boolean",
        "a bit boolean",
        "e bit boolean",
        "is_padding boolean",
    ];

    println!("# Free cells (not used in any non-zero constraint):");
    for column_index in 0..ctx.plaf.columns.witness.len() {
        // Map from (cell) -> [offsets with no constraints]
        let mut cell_poly_map_offsets = HashMap::new();
        for offset in 0..ctx.plaf.info.num_rows {
            let cell = Cell::new(Column::new(ColumnKind::Witness, column_index), offset);
            // Skip cells manually set as witness
            if ctx.witness.witness[column_index][offset].is_some() {
                // println!("DBG set {}", offset);
                continue;
            }
            // Skip cells that have a single possible value after bounds analysis
            if let Some(attrs) = ctx.analysis.borrow().vars_attrs.get(&cell) {
                if attrs.bound != ctx.bound_default {
                    if attrs.bound.unique().is_some() {
                        // println!("DBG analyzed {}", offset);
                        continue;
                    }
                }
            }
            let mut is_free = true;
            if let Some(poly_refs) = ctx.cell_expr_map.get(&cell) {
                for poly_ref in poly_refs {
                    let (poly_offset, poly) = poly_ref.get(&ctx.plaf);
                    if skip_patterns
                        .iter()
                        .any(|skip_pattern| poly.name.contains(skip_pattern))
                    {
                        continue;
                    }

                    let exp = ctx.eval_partial::<true>(&poly.exp, poly_offset);
                    // println!(
                    //     "DBG {} {} {}",
                    //     offset,
                    //     poly.name,
                    //     ctx.disp_expr_cell(&exp)
                    // );
                    // Skip whenever the partial evaluated expression doesn't contain the cell
                    // variable anymore.
                    if !exp.vars().contains(&cell) {
                        continue;
                    }
                    if !exp.is_zero() {
                        is_free = false;
                        break;
                    }
                }
            }
            if is_free {
                // print!(
                //     "ALERT: non-i/o cell {} only used in one nonzero-constraint: ",
                //     CellDisplay {
                //         c: &cell,
                //         plaf: &ctx.plaf
                //     }
                // );
                // let (poly_offset, poly, _exp) = &nonzero_exps[0];
                // println!(
                //     "\"{}\"",
                //     poly.name,
                //     // ctx.disp_expr_cell(&exp)
                // );
                cell_poly_map_offsets
                    .entry(column_index)
                    .and_modify(|offsets: &mut Vec<usize>| {
                        offsets.push(offset);
                    })
                    .or_insert(vec![offset]);
            }
        }
        for (column_index, offsets) in cell_poly_map_offsets.iter() {
            print!(
                "column {} at offsets ",
                ctx.plaf.columns.witness[*column_index].name(),
            );
            print_array_ranges(&offsets);
            println!();
        }
    }
}

fn analyze_io(ctx: &Context) {
    let skip_patterns: [&str; 0] = [
        // "w bit boolean",
        // "a bit boolean",
        // "e bit boolean",
        // "is_padding boolean",
    ];

    println!("# i/o not used in any non-zero constraint:");
    for cell in ctx.input_set.iter().chain(ctx.output_set.iter()) {
        if let Some(poly_refs) = ctx.cell_expr_map.get(cell) {
            let mut zero_exps = Vec::new();
            let mut nonzero_exps_len = 0;
            for poly_ref in poly_refs {
                let (offset, poly) = poly_ref.get(&ctx.plaf);
                if skip_patterns
                    .iter()
                    .any(|skip_pattern| poly.name.contains(skip_pattern))
                {
                    continue;
                }
                nonzero_exps_len += 1;

                let exp = ctx.eval_partial::<true>(&poly.exp, offset);
                if exp.is_zero() {
                    zero_exps.push(poly);
                }
            }
            if nonzero_exps_len == 0 {
                println!(
                    "ALERT: i/o cell {} only used in zero-constraints:",
                    CellDisplay {
                        c: cell,
                        plaf: &ctx.plaf
                    }
                );
                for poly in &zero_exps {
                    println!("  - \"{}\"", poly.name);
                }
            }
        } else {
            println!(
                "ALERT: i/o cell {} not used in any poly gate",
                CellDisplay {
                    c: cell,
                    plaf: &ctx.plaf
                }
            );
        }
    }

    println!("# Non-i/o cells used in only one non-zero constraint:");
    let is_marked = |cell: &Cell| {
        if matches!(cell.column.kind, ColumnKind::Public) {
            false
        } else {
            ctx.mark_set[cell.column.index()][cell.offset()]
        }
    };
    for column_index in 0..ctx.plaf.columns.witness.len() {
        // Map from (cell, poly_ref) -> [offsets with a single constraint]
        // We don't use in selector-logic circuits;
        let mut cell_poly_map_offsets: HashMap<(usize, String), (Vec<usize>, Vec<usize>)> =
            HashMap::new();
        'offset_loop: for offset in 0..ctx.plaf.info.num_rows {
            let analyze_cell = Cell::new(Column::new(ColumnKind::Witness, column_index), offset);
            // Skip cell in mark_set
            if ctx.mark_set[column_index][offset] {
                continue;
            }
            // Skip i/o cells
            if ctx.input_set.contains(&analyze_cell) || ctx.output_set.contains(&analyze_cell) {
                continue;
            }
            // Skip cells manually set as witness
            if ctx.witness.witness[column_index][offset].is_some() {
                continue;
            }
            // Skip cells that have a single possible value after bounds analysis
            if let Some(attrs) = ctx.analysis.borrow().vars_attrs.get(&analyze_cell) {
                if attrs.bound != ctx.bound_default {
                    if attrs.bound.unique().is_some() {
                        continue;
                    }
                }
            }
            let mut unmarked_nonzero_exps = Vec::new();
            let mut marked_nonzero_exps = Vec::new();
            let mut nonzero_src_lookups = Vec::new();
            let mut nonzero_dst_lookups = Vec::new();
            let mut copy_list = vec![analyze_cell];
            // Keep a copy set of visited copy cells to avoid getting stuck in cycles
            let mut copy_set = HashSet::new();

            copy_set.insert(analyze_cell);
            'cell_loop: while let Some(cell) = copy_list.pop() {
                if matches!(cell.column.kind, ColumnKind::Fixed) {
                    // If the cell is copy constrained to a fixed cell, skip it.
                    continue 'offset_loop;
                }
                let marked = is_marked(&cell);
                if cell != analyze_cell {
                    // If we have already visited this cell via a previous copy constraint cycle
                    // and it was not marked, skip it.  With this check we avoid duplicates
                    // analysis: for example we avoid finding [w00[5], w01[8]] and then [w01[8],
                    // w00[5]].  But if w00[5] was marked, we would have skipped, so in that case
                    // we still want to analyze w01[8]
                    if cell.column.index() < analyze_cell.column.index() && !marked {
                        continue 'offset_loop;
                    }
                    if cell.column.index() == analyze_cell.column.index()
                        && cell.offset < analyze_cell.offset
                    {
                        continue 'offset_loop;
                    }
                }
                if let Some(poly_refs) = ctx.cell_expr_map.get(&cell) {
                    for poly_ref in poly_refs {
                        let (poly_offset, poly) = poly_ref.get(&ctx.plaf);
                        if skip_patterns
                            .iter()
                            .any(|skip_pattern| poly.name.contains(skip_pattern))
                        {
                            continue;
                        }

                        let exp = ctx.eval_partial::<true>(&poly.exp, poly_offset);
                        // Skip whenever the partial evaluated expression doesn't contain the cell
                        // variable anymore.
                        if !exp.vars().contains(&cell) {
                            continue;
                        }
                        if !exp.is_zero() {
                            if marked {
                                marked_nonzero_exps.push((poly_offset, poly, exp));
                            } else {
                                unmarked_nonzero_exps.push((poly_offset, poly, exp));
                            }
                        }
                        if unmarked_nonzero_exps.len() > 1 {
                            break 'cell_loop;
                        }
                    }
                }
                if let Some(lookup_refs) = ctx.cell_lookup_src_map.get(&cell) {
                    for lookup_ref in lookup_refs {
                        let (lookup_offset, lookup_expr) = lookup_ref.get(&ctx.plaf);
                        let exp = ctx.eval_partial::<true>(&lookup_expr, lookup_offset);
                        // Skip whenever the partial evaluated expression doesn't contain the cell
                        // variable anymore.
                        if !exp.vars().contains(&cell) {
                            continue;
                        }
                        if !exp.is_zero() {
                            nonzero_src_lookups.push((lookup_offset, lookup_expr, exp));
                        }
                    }
                }
                if let Some(lookup_refs) = ctx.cell_lookup_dst_map.get(&cell) {
                    for lookup_ref in lookup_refs {
                        let (lookup_offset, lookup_expr) = lookup_ref.get(&ctx.plaf);
                        let exp = ctx.eval_partial::<true>(&lookup_expr, lookup_offset);
                        // Skip whenever the partial evaluated expression doesn't contain the cell
                        // variable anymore.
                        if !exp.vars().contains(&cell) {
                            continue;
                        }
                        if !exp.is_zero() {
                            nonzero_dst_lookups.push((lookup_offset, lookup_expr, exp));
                        }
                    }
                }
                if matches!(cell.column.kind, ColumnKind::Witness) {
                    for copy_cell in &ctx.cell_copy_table[cell.column.index()][cell.offset()] {
                        if !copy_set.contains(copy_cell) {
                            copy_set.insert(*copy_cell);
                            copy_list.push(*copy_cell);
                        }
                    }
                }
            }
            if ((unmarked_nonzero_exps.len() + marked_nonzero_exps.len() == 1)
                || (unmarked_nonzero_exps.len() == 0 && marked_nonzero_exps.len() > 0))
                && nonzero_src_lookups.len() == 0
                && nonzero_dst_lookups.len() == 0
            {
                print!(" - ");
                for (i, cell_copy) in copy_set.iter().enumerate() {
                    let marked = is_marked(&cell_copy);
                    if i != 0 {
                        print!(", ");
                    }
                    if marked {
                        print!("*");
                    }
                    print!(
                        "{}",
                        CellDisplay {
                            c: &cell_copy,
                            plaf: &ctx.plaf
                        }
                    );
                }
                if unmarked_nonzero_exps.len() == 1 {
                    let (poly_offset, poly, exp) = &unmarked_nonzero_exps[0];
                    println!(" -> {}", ctx.disp_expr_cell(&exp));
                } else if unmarked_nonzero_exps.len() == 0 {
                    let (poly_offset, poly, exp) = &marked_nonzero_exps[0];
                    print!(" -> {}", ctx.disp_expr_cell(&exp));
                    if marked_nonzero_exps.len() == 1 {
                        println!(" (marked single!)");
                    } else {
                        println!(", ... (marked multi)");
                    }
                } else {
                    unreachable!();
                }
                // Disabled for selector-logic circuits
                // cell_poly_map_offsets
                //     .entry((column_index, poly.name.clone()))
                //     .and_modify(|(offsets, poly_offsets): &mut (Vec<usize>, Vec<usize>)| {
                //         offsets.push(offset);
                //         poly_offsets.push(*poly_offset);
                //     })
                //     .or_insert((vec![offset], vec![*poly_offset]));
            }
        }
        for ((column_index, poly_name), (offsets, poly_offsets)) in cell_poly_map_offsets.iter() {
            print!(
                "column {} by \"{}\" at offsets ",
                ctx.plaf.columns.witness[*column_index].name(),
                poly_name,
            );
            print_array_ranges(&offsets);
            print!(" by poly_offsets ");
            print_array_ranges(&poly_offsets);
            println!();
        }
    }
}

fn print_array_ranges(values: &[usize]) {
    let mut prev_value = values[0] + 1;
    let mut skipped = 0;
    print!("[");
    for (i, value) in values.iter().enumerate() {
        if i == 0 {
            print!("{}", value);
            prev_value = *value;
            continue;
        }
        if *value == prev_value + 1 {
            skipped += 1;
        } else {
            if skipped > 0 {
                print!("-{}, ", prev_value);
            } else {
                print!(", ");
            }
            print!("{}", value);
            skipped = 0;
        }
        prev_value = *value;
    }
    if skipped > 0 {
        print!("-{}", prev_value);
    }
    print!("]");
}

fn run(ctx: &mut Context, line: &str) {
    let terms: Vec<&str> = line.split_whitespace().collect();
    if terms.len() == 0 {
        return;
    }
    let cmd = &terms[0];
    let args = &terms[1..];
    if cmd == &"s" || cmd == &"set" {
        if args.len() != 2 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        set_witness(ctx, args[0], args[1]);
    } else if cmd == &"d" || cmd == &"dump" {
        if args.len() != 1 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        print_table(&ctx, args[0]);
    } else if cmd == &"p" || cmd == &"polys" {
        if args.len() != 1 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        print_polys(&ctx, args[0]);
    } else if cmd == &"l" || cmd == &"lookups" {
        if args.len() != 1 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        print_lookups(&ctx, args[0]);
    } else if cmd == &"a" || cmd == &"analyze" {
        ctx.analyze_all();
    } else if cmd == &"in" {
        if args.len() != 1 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        set_input(ctx, args[0]);
    } else if cmd == &"out" {
        if args.len() != 1 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        set_output(ctx, args[0]);
    } else if cmd == &"analyze_io" {
        // Perform analysis based on cells marked as input/output
        analyze_io(&ctx);
    } else if cmd == &"free_cells" {
        free_cells(&ctx);
    } else if cmd == &"u" || cmd == &"used" {
        if args.len() != 1 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        cell_used(ctx, args[0]);
    } else if cmd == &"unused_rows" {
        if args.len() != 2 {
            println!("Error: Invalid args: {:?}", args);
            return;
        }
        unused_rows(ctx, args[0], args[1]);
    } else if cmd == &"exit" {
        // TODO: Remove this ugly hack and propagate an exit signal properly
        panic!("exit");
    } else if cmd.starts_with("#") {
        return;
    } else {
        println!("Error: Unknown command {}", cmd);
        return;
    }
}
