// use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
// use eth_types::{bytecode, geth_types::GethData, ToWord, Word};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit};
// use mock::test_ctx::TestContext;
use num_bigint::BigUint;
use polyexen::{
    analyze::{bound_base, find_bounds_poly, Analysis},
    expr::{Expr, ExprDisplay},
    plaf::{
        backends::halo2::PlafH2Circuit,
        frontends::halo2::{gen_witness, get_plaf},
        Cell, CellDisplay, Lookup, Plaf, PlafDisplayBaseTOML, PlafDisplayFixedCSV, VarDisplay,
    },
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};
use zkevm_hashes::sha256::vanilla::tests::Sha256BitCircuit;
// use zkevm_circuits::{
//     bytecode_circuit::circuit::BytecodeCircuit,
//     copy_circuit::CopyCircuit,
//     evm_circuit::EvmCircuit,
//     exp_circuit::ExpCircuit,
//     keccak_circuit::KeccakCircuit,
//     pi_circuit::PiCircuit,
//     state_circuit::StateCircuit,
//     super_circuit::SuperCircuit,
//     tx_circuit::TxCircuit,
//     util::SubCircuit,
//     witness::{block_convert, Block},
// };

use std::{
    fs::File,
    io::{self, Write},
};

// use demo::utils::{alias_replace, gen_empty_block, name_challanges};
use demo::utils::{alias_replace, name_challanges};

fn write_files(name: &str, plaf: &Plaf) -> Result<(), io::Error> {
    let mut base_file = File::create(format!("out/{}.toml", name))?;
    let mut fixed_file = File::create(format!("out/{}_fixed.csv", name))?;
    write!(base_file, "{}", PlafDisplayBaseTOML(plaf))?;
    write!(fixed_file, "{}", PlafDisplayFixedCSV(plaf))?;
    Ok(())
}

/*
fn gen_small_block() -> Block<Fr> {
    let bytecode = bytecode! {
        PUSH32(0x1234)
        PUSH32(0x5678)
        ADD
        STOP
    };
    let block: GethData = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode)
        .unwrap()
        .into();

    let mut builder = BlockData::new_from_geth_data_with_params(
        block.clone(),
        CircuitsParams {
            max_rws: 128,
            max_txs: 1,
            max_calldata: 64,
            max_copy_rows: 128,
            max_bytecode: 32,
            max_keccak_rows: 128,
            max_evm_rows: 128,
            max_exp_steps: 128,
        },
    )
    .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    block
}
*/

#[derive(Default, Debug)]
struct VarPointers {
    polys: Vec<usize>,
    lookups: Vec<usize>,
    copys: Vec<usize>,
}

fn transform_to_raw_constraints(plaf: &Plaf) {
    // BEGIN RAW CONSTRAINTS
    let cell_fmt =
        |f: &mut fmt::Formatter<'_>, c: &Cell| write!(f, "{}", CellDisplay { c, plaf: &plaf });
    let mut var_map: HashMap<_, VarPointers> = HashMap::new();
    let mut raw_polys = Vec::new();
    // for offset in 0..16 {
    for offset in 0..plaf.info.num_rows {
        for poly in &plaf.polys {
            let mut exp = plaf.resolve(&poly.exp, offset);
            exp.simplify(&plaf.info.p);
            if exp.is_zero() {
                continue;
            }
            for var in exp.vars() {
                let pointers = var_map.entry(var).or_insert(VarPointers::default());
                pointers.polys.push(raw_polys.len());
            }
            raw_polys.push(exp);
            // println!(
            //     "{} = 0 # {}",
            //     ExprDisplay {
            //         e: &exp,
            //         var_fmt: cell_fmt
            //     },
            //     poly.name,
            // );
        }
    }
    let mut raw_lookups = Vec::new();
    for offset in 0..plaf.info.num_rows {
        for (lookup_num, lookup) in plaf.lookups.iter().enumerate() {
            let Lookup { name, exps } = lookup;
            let exps_lhs: Vec<_> = exps
                .0
                .iter()
                .map(|exp| {
                    let mut exp = plaf.resolve(&exp, offset);
                    exp.simplify(&plaf.info.p);
                    exp
                })
                .collect();
            if exps_lhs.iter().all(|exp| exp.is_zero()) {
                continue;
            }
            for exp in &exps_lhs {
                for var in exp.vars() {
                    let pointers = var_map.entry(var).or_insert(VarPointers::default());
                    pointers.lookups.push(raw_lookups.len());
                }
            }
            raw_lookups.push((exps_lhs, lookup_num));
            // print!("[");
            // for (i, exp) in exps_lhs.iter().enumerate() {
            //     if i != 0 {
            //         print!(", ")
            //     }
            //     print!(
            //         "{}",
            //         ExprDisplay {
            //             e: &exp,
            //             var_fmt: cell_fmt
            //         },
            //     );
            // }
            // print!("] in [");
            // for (i, exp) in exps.1.iter().enumerate() {
            //     if i != 0 {
            //         print!(", ")
            //     }
            //     print!(
            //         "{}",
            //         ExprDisplay {
            //             e: &exp,
            //             var_fmt: |f, v| plaf.fmt_var(f, v)
            //         },
            //     );
            // }
            // println!("] # {}", name);
        }
    }
    let mut raw_copys = Vec::new();
    for copy in &plaf.copys {
        let (column_a, column_b) = copy.columns;
        for offset in &copy.offsets {
            let cell_a = Cell {
                column: column_a,
                offset: offset.0,
            };
            let cell_b = Cell {
                column: column_b,
                offset: offset.1,
            };
            let pointers = var_map.entry(cell_a).or_insert(VarPointers::default());
            pointers.copys.push(raw_copys.len());
            let pointers = var_map.entry(cell_b).or_insert(VarPointers::default());
            pointers.copys.push(raw_copys.len());
            raw_copys.push((cell_a, cell_b));

            // println!(
            //     "{} - {}",
            //     CellDisplay {
            //         c: &cell_a,
            //         plaf: &plaf
            //     },
            //     CellDisplay {
            //         c: &cell_b,
            //         plaf: &plaf
            //     }
            // );
        }
    }
    // for (var, pointers) in var_map.iter() {
    //     print!(
    //         "{} in ",
    //         CellDisplay {
    //             c: var,
    //             plaf: &plaf
    //         }
    //     );
    //     println!("{:?}", pointers);
    // }
    // Collect copy sets (sets of cells that are constrained to be the same value)
    let mut copy_sets = Vec::new();
    let mut cleared = HashSet::new();
    let mut dup_vars_count = 0;
    for (index, (cell_main, cell_b)) in raw_copys.iter().enumerate() {
        if cleared.contains(&index) {
            continue;
        }
        cleared.insert(index);
        let mut next = vec![*cell_b];
        let mut copy_set = HashSet::new();
        while let Some(cell) = next.pop() {
            if cell == *cell_main {
                continue;
            }
            copy_set.insert(cell);
            if let Some(pointers) = var_map.get(&cell) {
                for copy_index in &pointers.copys {
                    if cleared.contains(copy_index) {
                        continue;
                    }
                    cleared.insert(*copy_index);
                    let (cell_a, cell_b) = raw_copys[*copy_index];
                    next.push(cell_a);
                    next.push(cell_b);
                }
            }
        }
        dup_vars_count += copy_set.len();
        copy_sets.push((cell_main, copy_set));
    }
    println!("dup_vars_count={}", dup_vars_count);
    // Apply copy constraint replacements
    for (cell_main, copy_set) in &copy_sets {
        for cell in copy_set {
            if let Some(pointers) = var_map.get(cell) {
                for poly_index in &pointers.polys {
                    let poly = raw_polys.get_mut(*poly_index).unwrap();
                    poly.replace_var(cell, &Expr::Var(**cell_main));
                }
                for lookup_index in &pointers.lookups {
                    let lookup = raw_lookups.get_mut(*lookup_index).unwrap();
                    for exp in lookup.0.iter_mut() {
                        exp.replace_var(cell, &Expr::Var(**cell_main));
                    }
                }
            }
        }
    }
    /*
    for copy in &copy_sets {
        print!(
            "{} <- [",
            CellDisplay {
                c: copy.0,
                plaf: &plaf
            }
        );
        for (i, copy_cell) in copy.1.iter().enumerate() {
            if i != 0 {
                print!(", ");
            }
            print!(
                "{}",
                CellDisplay {
                    c: copy_cell,
                    plaf: &plaf
                }
            );
        }
        println!("]");
    }
    */
    // END RAW CONSTRAINTS
}

/*
fn gen_circuit_plaf<C: Circuit<Fr> + SubCircuit<Fr>>(name: &str, k: u32, block: &Block<Fr>) {
    let circuit = C::new_from_block(&block);
    let mut plaf = get_plaf(k, &circuit).unwrap();
    name_challanges(&mut plaf);
    alias_replace(&mut plaf);
    // transform_to_raw_constraints(&plaf);
    write_files(name, &plaf).unwrap();
}
*/

/*
fn circuit_plaf_mock_prover<C: Circuit<Fr> + SubCircuit<Fr>>(name: &str, k: u32) {
    let block = gen_small_block();

    let circuit = C::new_from_block(&block);
    let mut plaf = get_plaf(k, &circuit).unwrap();
    name_challanges(&mut plaf);
    write_files(name, &plaf).unwrap();
    let instance = circuit.instance();
    let challenges = vec![Fr::from(0x100), Fr::from(0x100), Fr::from(0x100)];
    let wit = gen_witness(k, &circuit, &plaf, challenges, instance.clone()).unwrap();

    let plaf_circuit = PlafH2Circuit { plaf, wit };

    let mock_prover = MockProver::<Fr>::run(k, &plaf_circuit, instance).unwrap();
    mock_prover.assert_satisfied_par();
}
*/

fn demo_get_plaf() {
    // let block = gen_empty_block();
    // gen_circuit_plaf::<EvmCircuit<Fr>>("evm", 18, &block);
    // gen_circuit_plaf::<StateCircuit<Fr>>("state", 17, &block);
    // gen_circuit_plaf::<TxCircuit<Fr>>("tx", 19, &block);
    // gen_circuit_plaf::<BytecodeCircuit<Fr>>("bytecode", 9, &block);
    // gen_circuit_plaf::<CopyCircuit<Fr>>("copy", 9, &block);
    // gen_circuit_plaf::<KeccakCircuit<Fr>>("keccak", 11, &block);
    // gen_circuit_plaf::<ExpCircuit<Fr>>("exp", 10, &block);
    // gen_circuit_plaf::<PiCircuit<Fr>>("pi", 17, &block);
    // gen_circuit_plaf::<SuperCircuit<Fr>>("super", 19, &block);
}

fn demo_analysis() {
    // let block = gen_empty_block();
    // let circuit = BytecodeCircuit::<Fr>::new_from_block(&block);
    // let k = 9;
    let k: u32 = 10;
    let inputs = vec![vec![0x61], vec![0x01, 0x02, 0x03]];
    let circuit = Sha256BitCircuit::<Fr>::new(Some(2usize.pow(k) - 109usize), inputs, true);
    let mut plaf = get_plaf(k, &circuit).unwrap();
    plaf.simplify();
    name_challanges(&mut plaf);

    let p = BigUint::parse_bytes(b"100000000000000000000000000000000", 16).unwrap()
        - BigUint::from(159u64);
    let mut analysis = Analysis::new();
    let cell_fmt =
        |f: &mut fmt::Formatter<'_>, c: &Cell| write!(f, "{}", CellDisplay { c, plaf: &plaf });
    for offset in 0..plaf.info.num_rows {
        for poly in &plaf.polys {
            let mut exp = plaf.resolve(&poly.exp, offset);
            exp.simplify(&p);
            if exp.is_zero() {
                continue;
            }
            println!(
                "\"{}\" {}",
                poly.name,
                ExprDisplay {
                    e: &exp,
                    var_fmt: cell_fmt
                }
            );
            find_bounds_poly(&exp, &p, &mut analysis);
        }
    }
    let bound_base = bound_base(&p);
    for (cell, attrs) in &analysis.vars_attrs {
        if attrs.bound == bound_base {
            continue;
        }
        println!(
            "{}",
            CellDisplay {
                c: cell,
                plaf: &plaf
            }
        );
        println!("  {:?}", attrs.bound);
    }
}

/*
fn demo_plaf_halo2() {
    circuit_plaf_mock_prover::<BytecodeCircuit<Fr>>("bytecode", 9);
}
*/

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // demo_analysis();
    demo_get_plaf();
}
