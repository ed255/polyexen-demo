use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
use eth_types::geth_types::GethData;
use halo2_proofs::halo2curves::bn256::Fr;
use mock::test_ctx::TestContext;
use polyexen::plaf::Plaf;
use zkevm_circuits::witness::{block_convert, Block};

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
            max_bytecode: 128,
            max_keccak_rows: 1024,
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

pub fn name_challanges(plaf: &mut Plaf) {
    plaf.set_challange_alias(0, "r_word".to_string());
    plaf.set_challange_alias(1, "r_keccak".to_string());
    plaf.set_challange_alias(2, "r_evm_lookup".to_string());
}
