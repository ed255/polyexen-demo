```
sqlite3
.mode csv
.import bytecode_fixed.csv circuit
.mode box
SELECT * FROM circuit;
.save circuit.sqlite
CREATE TABLE tmp AS SELECT * FROM circuit;
```

```
echo ".mode csv\n.import bytecode_fixed.csv circuit\n.mode box\n.save circuit.sqlite" | sqlite3
```
