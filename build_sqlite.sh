#!/bin/sh

set -ex

for circuit in evm state tx bytecode copy keccak exp pi; do
    echo $circuit
    echo -e ".mode csv\n.import out/${circuit}_fixed.csv circuit\n.save out/${circuit}_fixed.sqlite" | sqlite3
done
