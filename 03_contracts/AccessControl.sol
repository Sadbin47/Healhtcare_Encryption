// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Encrypted EHR metadata and consent registry
/// @notice Stores references and permission state only. Plaintext EHR data,
///         AES keys, and private keys must remain off-chain.
contract AccessControl {
    struct RecordMetadata {
        string storageReference;
        bytes32 fileHash;
        address registeredBy;
        bool exists;
    }

    mapping(bytes32 => RecordMetadata) private records;
    mapping(bytes32 => mapping(address => bool)) private permissions;

    event RecordRegistered(
        bytes32 indexed recordId,
        string storageReference,
        bytes32 fileHash,
        address indexed registeredBy
    );
    event AccessGranted(bytes32 indexed recordId, address indexed doctor, address indexed grantedBy);
    event AccessRevoked(bytes32 indexed recordId, address indexed doctor, address indexed revokedBy);
    event RecordAccessed(bytes32 indexed recordId, address indexed doctor, uint256 timestamp);

    modifier existingRecord(string memory recordId) {
        require(records[_recordKey(recordId)].exists, "record does not exist");
        _;
    }

    modifier recordOwner(string memory recordId) {
        require(
            records[_recordKey(recordId)].registeredBy == msg.sender,
            "only record owner"
        );
        _;
    }

    function _recordKey(string memory recordId) internal pure returns (bytes32) {
        require(bytes(recordId).length > 0, "empty record id");
        return keccak256(bytes(recordId));
    }

    function registerRecord(
        string calldata recordId,
        string calldata storageReference,
        bytes32 fileHash
    ) external {
        require(bytes(recordId).length > 0, "empty record id");
        require(bytes(storageReference).length > 0, "empty storage reference");
        require(fileHash != bytes32(0), "empty file hash");
        bytes32 key = _recordKey(recordId);
        require(!records[key].exists, "record already registered");

        records[key] = RecordMetadata({
            storageReference: storageReference,
            fileHash: fileHash,
            registeredBy: msg.sender,
            exists: true
        });
        emit RecordRegistered(key, storageReference, fileHash, msg.sender);
    }

    function grantAccess(
        string calldata recordId,
        address doctorAddress
    ) external existingRecord(recordId) recordOwner(recordId) {
        require(doctorAddress != address(0), "invalid doctor address");
        permissions[_recordKey(recordId)][doctorAddress] = true;
        emit AccessGranted(_recordKey(recordId), doctorAddress, msg.sender);
    }

    function revokeAccess(
        string calldata recordId,
        address doctorAddress
    ) external existingRecord(recordId) recordOwner(recordId) {
        require(doctorAddress != address(0), "invalid doctor address");
        permissions[_recordKey(recordId)][doctorAddress] = false;
        emit AccessRevoked(_recordKey(recordId), doctorAddress, msg.sender);
    }

    function canAccess(
        string calldata recordId,
        address doctorAddress
    ) external view returns (bool) {
        bytes32 key = _recordKey(recordId);
        return records[key].exists && permissions[key][doctorAddress];
    }

    function getRecordMetadata(
        string calldata recordId
    ) external view existingRecord(recordId) returns (
        string memory storageReference,
        bytes32 fileHash,
        address registeredBy
    ) {
        RecordMetadata storage record = records[_recordKey(recordId)];
        return (record.storageReference, record.fileHash, record.registeredBy);
    }

    /// @notice Emit an access event only after the caller's grant is checked.
    function recordAccess(string calldata recordId)
        external
        existingRecord(recordId)
    {
        require(permissions[_recordKey(recordId)][msg.sender], "access not granted");
        emit RecordAccessed(_recordKey(recordId), msg.sender, block.timestamp);
    }
}
