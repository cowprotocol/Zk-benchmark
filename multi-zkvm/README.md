Run from /multi-zkvm

Make sure Docker is installed and running

For running in a docker environment

```
cargo run -p host -- \
  --zkvm sp1 \
  --msg "hello world" \
  --signers "$(seq -s ',' 0 47)"
```

For running in a RTX 4090/GPU instance

```
cargo +nightly run -p host-native -- \
  --zkvm sp1 \
  --msg "hello world" \
  --signers "$(seq -s ',' 0 47)"
```

options for zkVMs: sp1, pico, risc0, zisk.
