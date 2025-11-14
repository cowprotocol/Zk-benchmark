Run from /multi-zkvm

Make sure Docker is installed and running

```
cargo run -p host -- \
 --zkvm sp1 \
 --msg "hello world" \
 --signers "0,1,2,10,11,34,44,22,21,32,28,42"
```

options for zkVMs: sp1, pico, jolt, risc0, zisk.
