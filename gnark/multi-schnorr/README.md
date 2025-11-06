# Multi-Schnorr ZK Prover

Gnark groth16 circuit and tooling for verifying multiple Schnorr signatures against a Merkle-committed validator set.

### Circuit Overview

- **Validator set:** `S` of size `MaxK = 2^Depth`, with `depth` as the depth of merkle tree of validator pubic key hashes (currently set as 6) and inactive entries gated by `IsIgnore = 1`.
- **Merkle binding:** One-time MiMC tree built from `S` (`leaf = MiMC(Ax, Ay)`), less computation complexity than verifying each membership proof if k is large (eg. 2/3).
- **Membership:** Membership (per candidate): enforce that `(Ax,Ay)` matches exactly one leaf in `S`
- **Verification:** For each active entry, enforce `[S]G = R + [e]A`, with `e = MiMC(Rx, Ry, Ax, Ay, Message)`.
- **Counting:** `SumValid` accumulates all active, valid signatures, that can be compared against threshold in verifying smart contract

### Utility Functions

- **Key Generation:** Generates padded key pairs and persists them in keys.json.
- **Merkle Root Builder:** Builds the validator set Merkle root from generated public keys.
- **Candidate Builder:** Prepares candidate structures for proof creation.
- **Prepare Witness:** Creates complete witness data for the Groth16 circuit (Merkle membership, signatures, and valid signer tracking)

### Scripts

#### Setup

The `keygen.sh` and `setup_and_deploy_sepolia.sh` scripts together form the setup phase of the proving system and only need to be executed once for each circuit version.

They bind the validator set’s `Merkle root` and `threshold` to the `MultischnorrVerifier` contract and the `verifying key (VK)`to the `Verifier` contract, ensuring proofs from the matching `proving key (PK)` are valid only for that configuration.

- If the Merkle `depth` or circuit logic change, `setup_and_deploy_sepolia.sh` must be rerun and contracts redeployed, since the `VK` is hardcoded in the `Verifier` contract.
- If the validator `keys`, merkle `root` or `threshold` changes, the existing contracts can be used with the merkle root and threshold can be updated in the `MultischnorrVerifier` contract.

`keygen.sh`

- Generates validator key pairs and computes the Merkle root.
- Note: Since in the circuit, the depth of the merkle tree is set to 6, 64 (2^6) validator keys are generated. Because the circuit needs to be static and have fixed size at compile time, if in future, more validators are added, just update the ciruit.
  Ouputs: `keys.json` with public/private key pairs and `merkle_root.txt` with merkle root.

`setup_and_deploy_sepolia.sh`

- Compiles the cicuit and build the Proving Key (PK) and Verifying Key (VK), both of which can be made public.
  - Generates a `Verifier` contract that hardcodes the `VK` inside the smart contract for reproducible deployment.
- The setup and deploy script does the setup + deployment with the threshold and merkle root as constructor values.
- Note: The setup and deployment is required everytime the circuit changes and the keys change with each setup.
- Note: If the number of public inputs change, it will be needed to update the `MultischnorrVerifier` contract as it uses circuit specific inputs.
  Outputs: `circuit.r1cs`: compiled form of the circuit and `multischnorr.g16.pk` and `multischnorr.g16.vk` and `deployment.json` containing the addresses of `Verifier` and `MultischnorrVerifier` contracts.

#### Proof Generation & Verification

`prove.sh`

- Generates a Groth16 proof, converts it to a Solidity-compatible format, and verifies it on-chain by sending a transaction via `cast send`
- Builds the witness including the signatures for indices that signed, message and calculate the `sumValid`, which is the number of valid signatures that the circuit doesn't ignore.
- Sends a transaction with the proof to call the `verify` function on the `MultischnorrVerifier` contract.
  Ouputs: `proof.json` with a flattened version of proof and public inputs (public witness) required by the contract to verfiy the proof.

### Contracts

- `Verifier`: Auto-generated Groth16 verifier with the Verifying Key (VK) hardcoded as constants
- `MultiSchnorrVerifier`: Ownable wrapper around the verifier. It performs: validation of `threshold` against `sumValid`, validation of `merkle root` provided as input against `root` stored in contract by `owner`. Delegates to the `Verifier` with public inputs and proof data to verify the proof and if successful, emits a `ProofVerified` event.

### Running

The scripts can be run locally as well as in a devcontainer.

To run the scripts locally, make sure [go]("https://go.dev/doc/install) and [foundry]("https://getfoundry.sh/introduction/installation/") are installed in the system.

To run the scripts using the devcontainer, make sure VScode and [Docker]("https://www.docker.com/get-started/") is installed and running.

Running a Devcontainer: VS Code → Command Palette → “Dev Containers: Rebuild and Reopen in Container”

0. If not in the right directory (for running locally only)

```
cd gnark/multi-schnorr
```

1. Generate keys & Merkle root

```
bash ./keygen.sh
```

2. Compile, setup Groth16, and deploy contracts

```
bash ./setup_and_deploy_sepolia.sh \
  --private-key 0xYOUR_DEPLOYER_PK \
  --rpc-url https://sepolia.rpc.url \
  --threshold <uint256> \
  --etherscan-api-key ETHERSCAN_API_KEY
```

3. Generate a proof and submit on-chain

```
bash ./prove.sh \
  --rpc-url <URL> \
  --private-key <0xPK> \
  --msg "<message string or hex>" \
  --signers "space separated indices"
```

Note: The message here can be a string as well as a hex that can be formed using something like `abi.encode`.
