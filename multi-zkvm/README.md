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

You first need to install the toolchain for specified zkVM which can be done by cloning ere and `cd ere && bash scripts/sdk_installers/install_{zkvm_name}_sdk.sh`

```
cargo run -p host-native -- \
  --zkvm sp1 \
  --msg "hello world" \
  --signers "$(seq -s ',' 0 47)"
```

use +nightly-2025-08-04 for pico

```
RUST_LOG=info cargo +nightly-2025-08-04 run -p host-native --no-default-features --features pico -- \
  --zkvm pico \
  --msg "hello world" \
  --signers "$(seq -s ',' 0 47)"
```

options for zkVMs: sp1, pico, risc0, zisk.
