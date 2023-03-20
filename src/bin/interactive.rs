use halo2_proofs::halo2curves::bn256::Fr;
use num_bigint::BigUint;
use num_traits::Zero;
use polyexen::{
    analyze::{bound_base, find_bounds_poly, Analysis, Bound},
    expr::{Column, ColumnKind, Expr, ExprDisplay, PlonkVar as Var},
    plaf::{frontends::halo2::get_plaf, AliasMap, Cell, CellDisplay, Plaf, Witness},
};
use rustyline::{error::ReadlineError, DefaultEditor, Result};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt,
};
use zkevm_circuits::{
    bytecode_circuit::circuit::BytecodeCircuit,
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

use demo::{gen_empty_block, name_challanges};

#[derive(Debug, Clone, Copy)]
struct PolyRef {
    /// Row offset
    offset: usize,
    /// Index in Plaf.polys
    index: usize,
}

impl PolyRef {
    fn get<'a>(&self, plaf: &'a Plaf) -> (usize, &'a Expr<Var>) {
        (self.offset, &plaf.polys[self.index].exp)
    }
}

struct Context {
    plaf: Plaf,
    alias_map: AliasMap,
    cell_expr_map: HashMap<Cell, Vec<PolyRef>>,
    analysis: RefCell<Analysis<Cell>>,
    witness: Witness,
    bound_default: Bound,
}

impl Context {
    fn new(plaf: Plaf) -> Self {
        let p = &plaf.info.p;
        let analysis = Analysis::new();
        let witness = plaf.gen_empty_witness();
        let bound_default = bound_base(p);
        let alias_map = plaf.alias_map();
        let mut ctx = Context {
            plaf,
            alias_map,
            cell_expr_map: HashMap::new(),
            analysis: RefCell::new(analysis),
            witness,
            bound_default,
        };
        let cell_expr_map = ctx.cell_expr_map();
        ctx.cell_expr_map = cell_expr_map;
        ctx.analyze_all();
        ctx
    }

    fn resolve_wit(&self, index: usize, offset: usize) -> Option<BigUint> {
        if let Some(f) = &self.witness.witness[index][offset] {
            return Some(f.clone());
        }
        if let Some(attrs) = self.analysis.borrow().vars_attrs.get(&Cell {
            column: Column {
                kind: ColumnKind::Witness,
                index,
            },
            offset,
        }) {
            if let Some(f) = attrs.bound.unique() {
                return Some(f.clone());
            }
        }
        return None;
    }

    fn resolve_var<const WITNESS: bool>(&self, v: &Var, offset: usize) -> Expr<Cell> {
        match v {
            Var::ColumnQuery { column, rotation } => {
                let offset =
                    (offset as i32 + rotation).rem_euclid(self.plaf.info.num_rows as i32) as usize;
                match column.kind {
                    ColumnKind::Fixed => Expr::Const(
                        self.plaf.fixed[column.index][offset]
                            .clone()
                            .unwrap_or_else(BigUint::zero),
                    ),
                    ColumnKind::Witness => {
                        if WITNESS {
                            if let Some(f) = self.resolve_wit(column.index, offset) {
                                Expr::Const(f.clone())
                            } else {
                                Expr::Var(Cell {
                                    column: *column,
                                    offset,
                                })
                            }
                        } else {
                            Expr::Var(Cell {
                                column: *column,
                                offset,
                            })
                        }
                    }
                    _ => Expr::Var(Cell {
                        column: *column,
                        offset,
                    }),
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
                let exp = self.eval_partial(&poly.exp, offset);
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

    fn eval_partial(&self, exp: &Expr<Var>, offset: usize) -> Expr<Cell> {
        let p = &self.plaf.info.p;
        let mut exp = self
            .plaf
            .eval_partial(exp, &|v, o| self.resolve_var::<true>(v, o), offset);
        exp.simplify(p);
        exp
    }

    fn analyze_poly(&self, offset: usize, exp: &Expr<Var>) -> HashSet<Cell> {
        let p = &self.plaf.info.p;
        let mut exp = self.eval_partial(exp, offset);
        if exp.is_zero() {
            return HashSet::new();
        }
        if let Expr::Const(_f) = &exp {
            // TODO: Add more details
            println!("Warning: Poly constraint not satisfied");
        }
        let update1 = find_bounds_poly(&exp, p, &mut *self.analysis.borrow_mut());
        exp.normalize(p);
        let update2 = find_bounds_poly(&exp, p, &mut *self.analysis.borrow_mut());
        update1.iter().chain(update2.iter()).cloned().collect()
    }

    fn analyze(&mut self, mut set: HashSet<Cell>) {
        while set.len() != 0 {
            // println!("DBG Analyze set {:?}", set);
            let mut new_set = HashSet::new();
            for cell in &set {
                for poly_ref in self.cell_expr_map.get(cell).unwrap() {
                    let (offset, exp) = poly_ref.get(&self.plaf);
                    new_set.extend(self.analyze_poly(offset, exp).into_iter());
                }
            }
            // println!("DBG3 {}", self.analysis.borrow().vars_attrs.len());
            set = new_set;
        }
    }

    fn analyze_all(&mut self) {
        for offset in 0..self.plaf.info.num_rows {
            for poly in &self.plaf.polys {
                self.analyze_poly(offset, &poly.exp);
            }
        }
        // println!("DBG2 {}", self.analysis.borrow().vars_attrs.len());
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
            *alias = alias.replace("BYTECODE_", "");
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let block = gen_empty_block();
    let circuit = BytecodeCircuit::<Fr>::new_from_block(&block);
    let k = 9;
    let mut plaf = get_plaf(k, &circuit).unwrap();
    alias_replace(&mut plaf);
    plaf.simplify();
    name_challanges(&mut plaf);
    let mut ctx = Context::new(plaf);
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
            if i == 0 {
                print!("|");
            }
            print!(" {:width$} |", h, width = rows_width[i]);
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
            if i == 0 {
                print!("|");
            }
            print!(" {:-<width$} |", "", width = width);
        }
        println!();
        for row in &self.rows {
            Self::print_row(row, &rows_width);
        }
    }
}

fn print_polys(ctx: &Context, offset_str: &str) {
    let offset = usize::from_str_radix(offset_str, 10).unwrap();
    let p = &ctx.plaf.info.p;
    let cell_fmt =
        |f: &mut fmt::Formatter<'_>, c: &Cell| write!(f, "{}", CellDisplay { c, plaf: &ctx.plaf });
    for poly in &ctx.plaf.polys {
        let mut exp = ctx.eval_partial(&poly.exp, offset);
        exp.normalize(p);
        println!(
            "\"{}\"\n  ori: {}\n  res: {}",
            poly.name,
            ExprDisplay {
                e: &poly.exp,
                var_fmt: |f, v| ctx.plaf.fmt_var(f, v)
            },
            ExprDisplay {
                e: &exp,
                var_fmt: cell_fmt
            }
        );
    }
}

fn print_table(ctx: &Context, offset_str: &str) {
    let offset = usize::from_str_radix(offset_str, 10).unwrap();
    let mut column_names = Vec::new();
    column_names.push("#".to_string());
    for column in &ctx.plaf.columns.fixed {
        column_names.push(column.name().clone());
    }
    for column in &ctx.plaf.columns.public {
        column_names.push(column.name().clone());
    }
    for column in &ctx.plaf.columns.witness {
        column_names.push(column.name().clone());
    }
    let mut table = DisplayTable::new(column_names.into());
    for row in offset..offset + 16 {
        let mut row_values = Vec::new();
        row_values.push(Some(format!("{}", row)));
        for index in 0..ctx.plaf.columns.fixed.len() {
            row_values.push(ctx.plaf.fixed[index][row].clone().map(|v| format!("{}", v)));
        }
        for index in 0..ctx.plaf.columns.public.len() {
            // TODO
            row_values.push(ctx.plaf.fixed[index][row].clone().map(|v| format!("{}", v)));
        }
        for index in 0..ctx.plaf.columns.witness.len() {
            if let Some(f) = &ctx.witness.witness[index][row] {
                row_values.push(Some(format!("{}", f)));
                continue;
            }
            if let Some(attrs) = ctx.analysis.borrow().vars_attrs.get(&Cell {
                column: Column {
                    kind: ColumnKind::Witness,
                    index,
                },
                offset: row,
            }) {
                if attrs.bound != ctx.bound_default {
                    row_values.push(Some(format!("{}", attrs.bound)));
                    continue;
                }
            }
            row_values.push(
                ctx.witness.witness[index][row]
                    .clone()
                    .map(|v| format!("{}", v)),
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

fn set_witness(ctx: &mut Context, cell_str: &str, val_str: &str) {
    let val = if val_str == "?" {
        None
    } else {
        Some(u64::from_str_radix(val_str, 10).unwrap())
    };
    let (name_str, offset_str) = cell_str
        .split_once('[')
        .map(|(name, offset)| (name, &offset[..offset.len() - 1]))
        .unwrap();
    if let Some(var) = ctx.alias_map.0.get(name_str) {
        let offset = usize::from_str_radix(offset_str, 10).unwrap();
        match var {
            Var::ColumnQuery {
                column,
                rotation: _,
            } => match column.kind {
                ColumnKind::Witness => {
                    ctx.witness.witness[column.index][offset] = val.map(|v| BigUint::from(v));
                    ctx.analyze(
                        [Cell {
                            column: column.clone(),
                            offset,
                        }]
                        .into_iter()
                        .collect(),
                    );
                }
                ColumnKind::Public => unimplemented!(),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    } else {
        println!("Error: column \"{}\" not found", name_str);
    }
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
    } else if cmd == &"a" || cmd == &"analyze" {
        ctx.analyze_all();
    } else {
        println!("Error: Unknown command {}", cmd);
        return;
    }
}
