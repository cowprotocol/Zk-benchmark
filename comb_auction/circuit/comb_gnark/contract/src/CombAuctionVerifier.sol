// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import {Verifier} from "./Verifier.sol";

/// @notice Stores bidset root per auction after validator attestation,
/// then verifies a Groth16 proof of winner selection and stores winners.
/// Finally, exposes gating so only winners can settle.
contract CombAuctionVerifier is Ownable {
    Verifier public verifier;
    uint256 public constant WMAX = 30;
    uint256 public constant INPUT_LEN = 93;

    enum AuctionStatus {
        NONE,
        ROOT_POSTED,
        WINNERS_VERIFIED
    }

    struct Winner {
        uint256 solutionId;
        address solver;
        uint256 score;
    }

    // auctionId => status/root/winners
    mapping(uint256 => AuctionStatus) public status;
    mapping(uint256 => bytes32) public bidsetRoot;
    mapping(uint256 => uint256) public winnersLen;
    mapping(uint256 => Winner[]) public winners;
    mapping(uint256 => mapping(address => bool)) public isWinner;

    event RootPosted(uint256 indexed auctionId, bytes32 bidsetRoot);
    event WinnersVerified(uint256 indexed auctionId, uint256 winnersLen);

    error RootAlreadyPosted();
    error RootNotPosted();
    error WinnersAlreadyVerified();
    error BadPublicInputs();
    error BadWinnerEncoding();

    constructor(Verifier _verifier, address _owner) Ownable(_owner) {
        require(address(_verifier) != address(0), "verifier=0");
        verifier = _verifier;
    }

    function updateVerifier(Verifier newVerifier) external onlyOwner {
        require(address(newVerifier) != address(0), "verifier=0");
        verifier = newVerifier;
    }

    /// @notice Validators attest to bidsetRoot for auctionId.
    function postRoot(
        uint256 auctionId,
        bytes32 root,
        bytes calldata /*signatures*/ // intentionally unused for now
    ) external {
        if (status[auctionId] != AuctionStatus.NONE) revert RootAlreadyPosted();

        // TODO: verify validator signatures for (auctionId, root, domainSeparator)

        bidsetRoot[auctionId] = root;
        status[auctionId] = AuctionStatus.ROOT_POSTED;

        emit RootPosted(auctionId, root);
    }

    /// @notice Solver submits Groth16 proof; if valid stores winners for auctionId.
    function submitWinnersProof(
        uint256 auctionId,
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[93] calldata input
    ) external {
        if (status[auctionId] == AuctionStatus.NONE) revert RootNotPosted();
        if (status[auctionId] == AuctionStatus.WINNERS_VERIFIED)
            revert WinnersAlreadyVerified();

        if (input[0] != auctionId) revert BadPublicInputs();
        if (bytes32(input[1]) != bidsetRoot[auctionId])
            revert BadPublicInputs();

        uint256 wLen = input[2];
        if (wLen > WMAX) revert BadPublicInputs();

        // Reverts internally if proof is invalid.
        verifier.verifyProof(proof, commitments, commitmentPok, input);

        winnersLen[auctionId] = wLen;
        delete winners[auctionId];

        uint256 off = 3;
        for (uint256 w = 0; w < wLen; w++) {
            uint256 solId = input[off];
            address solverAddr = address(uint160(input[off + 1]));
            uint256 score = input[off + 2];

            winners[auctionId].push(
                Winner({solutionId: solId, solver: solverAddr, score: score})
            );
            isWinner[auctionId][solverAddr] = true;
            off += 3;
        }

        status[auctionId] = AuctionStatus.WINNERS_VERIFIED;
        emit WinnersVerified(auctionId, wLen);
    }

    function getWinners(
        uint256 auctionId
    ) external view returns (Winner[] memory out) {
        uint256 len = winnersLen[auctionId];
        out = new Winner[](len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = winners[auctionId][i];
        }
    }
}
