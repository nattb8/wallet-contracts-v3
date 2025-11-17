// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Wallet } from "../../Wallet.sol";
import { Implementation } from "../Implementation.sol";
import { Storage } from "../Storage.sol";
import { BaseAuth } from "./BaseAuth.sol";

/// @title IImmutableSigner
/// @notice Interface for the ImmutableSigner contract
interface IImmutableSigner {
  struct ExpirableSigner {
    address signer;
    uint256 validUntil;
  }
  
  function primarySigner() external view returns (address);
  function rolloverSigner() external view returns (ExpirableSigner memory);
}

/// @title Stage1Auth
/// @author Agustin Aguilar
/// @notice Stage 1 auth contract
contract Stage1Auth is BaseAuth, Implementation {

  /// @notice Error thrown when the image hash is zero
  error ImageHashIsZero();

  /// @notice Initialization code hash
  bytes32 public immutable INIT_CODE_HASH;
  /// @notice Factory address
  address public immutable FACTORY;
  /// @notice Stage 2 implementation address
  address public immutable STAGE_2_IMPLEMENTATION;
  /// @notice ImmutableSigner contract address
  address public immutable IMMUTABLE_SIGNER_CONTRACT;

  /// @dev keccak256("org.arcadeum.module.auth.upgradable.image.hash")
  bytes32 internal constant IMAGE_HASH_KEY = bytes32(0xea7157fa25e3aa17d0ae2d5280fa4e24d421c61842aa85e45194e1145aa72bf8);

  /// @notice Emitted when the image hash is updated
  event ImageHashUpdated(bytes32 newImageHash);

  constructor(address _factory, address _stage2, address _immutableSignerContract) {
    // Build init code hash of the deployed wallets using that module
    bytes32 initCodeHash = keccak256(abi.encodePacked(Wallet.creationCode, uint256(uint160(address(this)))));

    INIT_CODE_HASH = initCodeHash;
    FACTORY = _factory;
    STAGE_2_IMPLEMENTATION = _stage2;
    IMMUTABLE_SIGNER_CONTRACT = _immutableSignerContract;
  }

  function _updateImageHash(
    bytes32 _imageHash
  ) internal virtual override {
    // Update imageHash in storage
    if (_imageHash == bytes32(0)) {
      revert ImageHashIsZero();
    }
    Storage.writeBytes32(IMAGE_HASH_KEY, _imageHash);
    emit ImageHashUpdated(_imageHash);

    // Update wallet implementation to stage2 version
    _updateImplementation(STAGE_2_IMPLEMENTATION);
  }

  /// @notice Calculate imageHash for Immutable-only signer (V1 format)
  /// @dev Uses V1 imageHash format: keccak256(abi.encode(threshold, signers[]))
  ///      This matches the signature encoding used by walletMultiSign helper
  function imageHashOfImmutableSigner() internal view returns (bytes32 primary, bytes32 rollover) {
    // Get primary signer
    address primarySignerEOA = IImmutableSigner(IMMUTABLE_SIGNER_CONTRACT).primarySigner();
    
    // V1 format: keccak256(abi.encode(threshold, [signers]))
    address[] memory primarySigners = new address[](1);
    primarySigners[0] = primarySignerEOA;
    primary = keccak256(abi.encode(uint256(1), primarySigners));
    
    // Get rollover signer (if exists and valid)
    IImmutableSigner.ExpirableSigner memory rolloverSigner = IImmutableSigner(IMMUTABLE_SIGNER_CONTRACT).rolloverSigner();
    
    if (block.timestamp <= rolloverSigner.validUntil && rolloverSigner.signer != address(0)) {
      address[] memory rolloverSigners = new address[](1);
      rolloverSigners[0] = rolloverSigner.signer;
      rollover = keccak256(abi.encode(uint256(1), rolloverSigners));
    } else {
      rollover = bytes32(0);
    }
  }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    // Standard validation: Check if CFA matches (for normal deployment)
    address expectedAddress = address(uint160(uint256(
      keccak256(abi.encodePacked(hex"ff", FACTORY, _imageHash, INIT_CODE_HASH))
    )));
    
    if (expectedAddress == address(this)) {
      return true;  // Normal case: CFA matches
    }
    
    // BOOTSTRAP MODE: Check if signed by Immutable signer only
    // This allows deploying a wallet with a different salt (from another chain)
    // and using Immutable-only signature to authorize the first transaction
    (bytes32 primaryImageHash, bytes32 rolloverImageHash) = imageHashOfImmutableSigner();
    
    if (_imageHash == primaryImageHash) {
      return true;  // Bootstrap with primary signer
    }
    
    if (rolloverImageHash != bytes32(0) && _imageHash == rolloverImageHash) {
      return true;  // Bootstrap with rollover signer
    }
    
    return false;  // Invalid signature
  }

}

