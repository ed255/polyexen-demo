# Plaf demo

This is a demo of Plaf: Plonkish Arithmetiation Format on the zkevm-circuits


Steps to run this:
- 1. Clone these three repositories in the same folder:
    - https://github.com/ed255/halo2 (Make sure you're at `feature/wip-polyexen` branch)
    - https://github.com/ed255/zkevm-circuits (Make sure you're at `feature/wip-polyexen` branch)
    - https://github.com/ed255/demo
    - https://github.com/Dhole/polyexen
- 2. Enter the `demo` directory and run it:
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
