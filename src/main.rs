use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
use eth_types::{bytecode, geth_types::GethData, ToWord, Word};
use halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit};
use mock::test_ctx::TestContext;
use polyexen::ir::*;
use zkevm_circuits::witness::block_convert;
use zkevm_circuits::{
    bytecode_circuit::circuit::BytecodeCircuit, copy_circuit::CopyCircuit, evm_circuit::EvmCircuit,
    exp_circuit::ExpCircuit, keccak_circuit::keccak_packed_multi::KeccakCircuit,
    pi_circuit::PiTestCircuit as PiCircuit, state_circuit::StateCircuit,
    super_circuit::SuperCircuit, tx_circuit::TxCircuit, util::SubCircuit,
};

use std::fs::File;
use std::io::{self, Write};

fn name_challanges(plaf: &mut Plaf) {
    plaf.set_challange_alias(0, "r_word".to_string());
    plaf.set_challange_alias(1, "r_keccak".to_string());
    plaf.set_challange_alias(2, "r_evm_lookup".to_string());
}

fn write_files(name: &str, plaf: &Plaf) -> Result<(), io::Error> {
    let mut base_file = File::create(format!("out/{}.toml", name))?;
    let mut fixed_file = File::create(format!("out/{}_fixed.csv", name))?;
    write!(base_file, "{}", PlafDisplayBaseTOML(plaf))?;
    write!(fixed_file, "{}", PlafDisplayFixedCSV(plaf))?;
    Ok(())
}

fn gen_circuit_plaf<C: Circuit<Fr> + SubCircuit<Fr>>(name: &str, k: u32) {
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
            keccak_padding: Some(1024),
        },
    )
    .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
    // TODO: Remove once these parameters are moved to CIrcuitsParams
    block.evm_circuit_pad_to = 128;
    block.exp_circuit_pad_to = 128;

    let circuit = C::new_from_block(&block);
    let mut plaf = gen_plaf(k, &circuit).unwrap();
    name_challanges(&mut plaf);
    write_files(name, &plaf).unwrap();
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    gen_circuit_plaf::<EvmCircuit<Fr>>("evm", 18);
    gen_circuit_plaf::<StateCircuit<Fr>>("state", 17);
    gen_circuit_plaf::<TxCircuit<Fr>>("tx", 19);
    gen_circuit_plaf::<BytecodeCircuit<Fr>>("bytecode", 9);
    gen_circuit_plaf::<CopyCircuit<Fr>>("copy", 9);
    gen_circuit_plaf::<KeccakCircuit<Fr>>("keccak", 11);
    gen_circuit_plaf::<ExpCircuit<Fr>>("exp", 9);
    gen_circuit_plaf::<PiCircuit<Fr, 1, 64>>("pi", 17);
    // gen_circuit_plaf::<SuperCircuit<Fr, 1, 64, 0x100>>("super", 19);
}
