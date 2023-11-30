use axiom_core::tests::integration::test_mainnet_header_chain_provider;
use axiom_query::{
    components::results::tests::results_root_test_circuit,
    subquery_aggregation::tests::subquery_agg_test_circuit,
    verify_compute::tests::verify_compute_test_circuit,
};
use polyexen::{
    halo2_proofs::halo2curves::bn256::Fr,
    plaf::frontends::halo2::{gen_witness, get_plaf},
};

fn verify_compute() {
    let (k, circuit) = verify_compute_test_circuit();
    let mut plaf = get_plaf(k, &circuit).unwrap();
    std::env::set_var("DEBUG", "1");
    let witness = Some(gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], vec![]).unwrap());
}

fn results_root() {
    let (k, instances, circuit) = results_root_test_circuit();
    let mut plaf = get_plaf(k, &circuit).unwrap();
    std::env::set_var("DEBUG", "1");
    let witness =
        Some(gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], vec![instances]).unwrap());
}

fn subquery_aggregation() {
    let (k, instances, circuit) = subquery_agg_test_circuit();
    let mut plaf = get_plaf(k, &circuit).unwrap();
    std::env::set_var("DEBUG", "1");
    let witness = Some(gen_witness(k, &circuit, &plaf, vec![Fr::from(0x100)], instances).unwrap());
}

fn axiom_aggregation_1() {}

fn axiom_aggregation_2() {}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    subquery_aggregation();
    // test_mainnet_header_chain_provider();
}
