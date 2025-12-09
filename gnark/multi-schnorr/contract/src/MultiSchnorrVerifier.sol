// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import {Verifier} from "./Verifier.sol";

contract MultiSchnorrVerifier is Ownable {
    Verifier public verifier;
    uint256 public threshold;
    uint256 public merkleRoot;

    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event ThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);
    event MerkleRootUpdated(uint256 oldRoot, uint256 newRoot);
    event ProofVerified(
        bytes message,
        uint256 merkleRoot,
        uint256 messageFr,
        uint256 sumValid
    );

    error InvalidMerkleRoot();
    error InsufficientSignatures();

    constructor(
        Verifier _verifier,
        uint256 _threshold,
        uint256 _root,
        address _owner
    ) Ownable(_owner) {
        require(address(_verifier) != address(0), "verifier=0");
        require(_threshold > 0, "threshold=0");
        verifier = _verifier;
        threshold = _threshold;
        merkleRoot = _root;
    }

    uint256 constant R =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    function updateVerifier(Verifier newVerifier) external onlyOwner {
        require(address(newVerifier) != address(0), "verifier=0");
        address old = address(verifier);
        verifier = newVerifier;
        emit VerifierUpdated(old, address(newVerifier));
    }

    function updateThreshold(uint256 t) external onlyOwner {
        require(t > 0, "threshold=0");
        uint256 old = threshold;
        threshold = t;
        emit ThresholdUpdated(old, t);
    }

    function updateMerkleRoot(uint256 r) external onlyOwner {
        require(r != 0, "root=0");
        uint256 old = merkleRoot;
        merkleRoot = r;
        emit MerkleRootUpdated(old, r);
    }

    function keccakToFr(bytes memory m) internal pure returns (uint256) {
        return uint256(keccak256(m)) % R;
    }

    /// @notice Verify proof binds {merkleRoot, hashToFr(message), sumValid}
    /// and emits the original message.
    function verify(
        uint256[8] calldata proof, // if compressed: change to uint256[4]
        bytes calldata message,
        uint256 _merkleRoot,
        uint256 sumValid
    ) external {
        if (sumValid < threshold) {
            revert InsufficientSignatures();
        }
        if (_merkleRoot != merkleRoot) {
            revert InvalidMerkleRoot();
        }
        uint256 messageFr = keccakToFr(message);
        uint256[3] memory input = [merkleRoot, messageFr, sumValid];

        verifier.verifyProof(proof, input);

        emit ProofVerified(message, merkleRoot, messageFr, sumValid);
    }
}
