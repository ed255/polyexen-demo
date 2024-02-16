# Plaf demo

This is a demo of Plaf: Plonkish Arithmetiation Format on the zkevm-circuits


Steps to run this:
- 1. Clone these three repositories in the same folder:
    - https://github.com/ed255/halo2 (Checkout `9d5c76e606c5bebb61c4cc22d3bf065b364f971d`)
    - https://github.com/ed255/zkevm-circuits (Checkout `344bbcd6a19314dc500dd2aa10f44ebdce723aec`)
    - https://github.com/ed255/halo2wrong (Checkout `0823e711de5c1b79a906f7aa1dd3b8686b6501ca`)
    - https://github.com/ed255/polyexen-demo (Checkout `17f5c37125cb46f53e44a14e1789afbaa485845c`)
    - https://github.com/Dhole/polyexen (Checkout `fc747aab032125fba2f8415405fe84fc43bd9e61`)
- 2. Enter the `polyexen-demo` directory and run it:
    - `git checkout 2023-03-15`
    - `mkdir -p out`
    - `cargo run`
- 3. Build sqlite databases for fixed columns assignations:
    - `./build_sqlite.sh`

You can find the circuit documents in `demo/out` 
- With extension `.toml` is a circuit description that contains:
    - Circuit info (number of rows, challenges used)
    - Columns used (public is halo2's instance, witness is halo2's advice)
    - arithmetic constraints
    - lookups
    - copy constraints
- With extension `_fixed.csv` is a CSV of the fixed columns assignment
- For convenience, with extension `_fixed.sqlite` is sqlite databases wiht the fixed columns assignents.  They can be browsed with `sqlitebrowser`.

You can also see the output directly by downloading it from https://github.com/ed255/polyexen-demo/releases/download/2023-03-15/out.tgz
