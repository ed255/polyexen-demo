// use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
use convert_case::{Case, Casing};
// use eth_types::geth_types::GethData;
use polyexen::halo2_proofs::halo2curves::bn256::Fr;
// use mock::test_ctx::TestContext;
use polyexen::plaf::Plaf;
// use zkevm_circuits::witness::{block_convert, Block};

/*
pub fn gen_empty_block() -> Block<Fr> {
    let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
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
            max_keccak_rows: 1024,
            max_evm_rows: 128,
            max_exp_steps: 32,
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

pub fn name_challanges(plaf: &mut Plaf) {
    plaf.set_challange_alias(0, "rWord".to_string());
    plaf.set_challange_alias(1, "rKeccak".to_string());
    plaf.set_challange_alias(2, "rEvmLookup".to_string());
}

pub fn alias_replace(plaf: &mut Plaf) {
    for aliases in plaf
        .columns
        .fixed
        .iter_mut()
        .map(|c| &mut c.aliases)
        .chain(plaf.columns.public.iter_mut().map(|c| &mut c.aliases))
        .chain(plaf.columns.witness.iter_mut().map(|c| &mut c.aliases))
    {
        for alias in aliases.iter_mut() {
            for (before, after) in [
                ("LOOKUP_", "lu."),
                ("lookup", "lu"),
                ("normalize", "norm"),
                ("context", "ctx"),
                ("address", "addr"),
                ("input", "in"),
                ("output", "out"),
                ("inverse", "inv"),
                ("binary", "bin"),
                ("initial", "init"),
                ("difference", "diff"),
                ("first", "fst"),
                // Bytecode
                ("BYTECODE_", "bc."),
                // Bytecode Chiquito
                ("halo2 fixed ", ""),
                ("halo2 advice ", ""),
                ("srcm forward ", "fwd_"),
                ("srcm internal signal ", "int_"),
                ("length", "len"),
                ("value", "val"),
                // EVM
                ("EVM_", "ev."),
                // Exp
                ("EXP_", "ex."),
                ("GADGET_MUL_ADD_", "MulAdd."),
                ("_col", "_c"),
                ("identifier", "id"),
                ("parity_check", "parChe"),
                // Keccak
                ("KECCAK_", "kc."),
                // State
                ("STATE", "st."),
                // CamelCase
                ("0_", "0."),
                ("1_", "1."),
                ("2_", "2."),
                ("3_", "3."),
                ("4_", "4."),
                ("5_", "5."),
                ("6_", "6."),
                ("7_", "7."),
                ("8_", "8."),
                ("9_", "9."),
            ] {
                *alias = alias.replace(before, after);
            }
            *alias = alias.to_case(Case::Camel);
        }
    }
}
