// use axiom_core::tests::integration::eth_block_header_test_circuit;
// use axiom_query::{
//     components::results::tests::results_root_test_circuit,
//     subquery_aggregation::tests::subquery_agg_test_circuit,
//     verify_compute::tests::verify_compute_test_circuit,
// };
use axiom_client::tests::keccak::all_subquery_test_circuit;
use axiom_query::{
    components::results::tests::results_root_test_circuit,
    verify_compute::tests::{
        aggregation::verify_compute_agg_test_circuit, verify_compute_test_circuit,
        verify_no_compute_test_circuit,
    },
};
use polyexen::{
    halo2_proofs::halo2curves::bn256::Fr,
    plaf::frontends::halo2::{gen_witness, get_plaf},
};

// fn verify_compute() {
//     // let (k, circuit) = verify_no_compute_test_circuit();
//     let (k, circuit) = verify_compute_test_agg_circuit();
//     let mut plaf = get_plaf(k, &circuit).unwrap();
//     // std::env::set_var("DEBUG", "1");
//     log::info!("gen_witness verify_compute");
//     let witness = gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], vec![]).unwrap();
//     println!("w00[0]={:?}", witness.witness[0][0]);
// }

fn results_root() {
    let (k, instances, circuit) = results_root_test_circuit();
    let mut plaf = get_plaf(k, &circuit).unwrap();
    // std::env::set_var("DEBUG", "1");
    log::info!("gen_witness results_root");
    let witness = gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], vec![instances]).unwrap();
    println!("w00[0]={:?}", witness.witness[0][0]);
}

fn all_subquery() {
    let (k, circuit) = all_subquery_test_circuit();
    let mut plaf = get_plaf(k, &circuit).unwrap();
    std::env::set_var("DEBUG", "1");
    log::info!("gen_witness results_root");
    let witness = gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], vec![vec![]]).unwrap();
    println!("w00[0]={:?}", witness.witness[0][0]);
}

// fn subquery_aggregation() {
//     let (k, instances, circuit) = subquery_agg_test_circuit();
//     let mut plaf = get_plaf(k, &circuit).unwrap();
//     // std::env::set_var("DEBUG", "1");
//     log::info!("gen_witness subquery_aggregation");
//     let witness =
//         gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], instances.clone()).unwrap();
//     println!("w00[0]={:?}", witness.witness[0][0]);
// }
//
// fn axiom_aggregation_1() {}
//
// fn axiom_aggregation_2() {}
//
// fn eth_block_header_leaf() {
//     let sample = eth_block_header_test_circuit("leaf");
//     let k = sample.k;
//     let circuit = sample.leaf.unwrap();
//     let instances = circuit.instances();
//     let mut plaf = get_plaf(k, &circuit).unwrap();
//     log::info!("gen_witness eth_block_header_leaf");
//     let witness =
//         gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], instances.clone()).unwrap();
//     println!("w00[0]={:?}", witness.witness[0][0]);
// }

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    all_subquery();
    // subquery_aggregation();
    // results_root();
    // test_mainnet_header_chain_provider();
    // verify_compute();
}
