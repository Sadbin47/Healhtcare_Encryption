"""Web3 client for the Phase 5 encrypted-record access-control contract."""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional


class BlockchainError(RuntimeError):
    """Base error for blockchain client failures."""


class BlockchainDependencyError(BlockchainError):
    """Raised when Web3 is needed but is not installed."""


class BlockchainValidationError(ValueError):
    """Raised for malformed identifiers, hashes, or addresses."""


CONTRACT_ABI: list[dict[str, Any]] = [
    {
        "inputs": [
            {"internalType": "string", "name": "recordId", "type": "string"},
            {"internalType": "string", "name": "storageReference", "type": "string"},
            {"internalType": "bytes32", "name": "fileHash", "type": "bytes32"},
        ],
        "name": "registerRecord",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "string", "name": "recordId", "type": "string"},
            {"internalType": "address", "name": "doctorAddress", "type": "address"},
        ],
        "name": "grantAccess",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "string", "name": "recordId", "type": "string"},
            {"internalType": "address", "name": "doctorAddress", "type": "address"},
        ],
        "name": "revokeAccess",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "string", "name": "recordId", "type": "string"},
            {"internalType": "address", "name": "doctorAddress", "type": "address"},
        ],
        "name": "canAccess",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "string", "name": "recordId", "type": "string"}],
        "name": "getRecordMetadata",
        "outputs": [
            {"internalType": "string", "name": "storageReference", "type": "string"},
            {"internalType": "bytes32", "name": "fileHash", "type": "bytes32"},
            {"internalType": "address", "name": "registeredBy", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "string", "name": "recordId", "type": "string"}],
        "name": "recordAccess",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

_HEX_64 = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def normalize_file_hash(file_hash: str | bytes) -> bytes:
    """Normalize a SHA-256 digest into the 32-byte ABI value."""

    if isinstance(file_hash, bytes):
        if len(file_hash) != 32:
            raise BlockchainValidationError("file_hash must be exactly 32 bytes")
        return file_hash
    if not isinstance(file_hash, str) or not _HEX_64.fullmatch(file_hash):
        raise BlockchainValidationError("file_hash must be a 64-character SHA-256 hex digest")
    return bytes.fromhex(file_hash.removeprefix("0x"))


def validate_address(address: str) -> str:
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address) or int(address[2:], 16) == 0:
        raise BlockchainValidationError("doctor address must be a non-zero 20-byte hex address")
    return address


def _load_web3() -> Any:
    try:
        from web3 import Web3
    except ImportError as error:  # pragma: no cover - environment dependent.
        raise BlockchainDependencyError(
            "web3 is required for live blockchain connections; install requirements.txt"
        ) from error
    return Web3


class BlockchainClient:
    """Small client that separates read calls from signed transactions.

    A ``contract`` can be injected for deterministic tests. For live use,
    provide ``provider_url``, ``contract_address``, and ``private_key``.
    """

    def __init__(
        self,
        *,
        provider_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        private_key: Optional[str] = None,
        web3: Any = None,
        contract: Any = None,
        account: Optional[str] = None,
        abi: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        self.web3 = web3
        self.contract = contract
        self.abi = abi or CONTRACT_ABI
        self.private_key = private_key
        self.account = account

        if self.contract is not None:
            return
        if not provider_url or not contract_address:
            raise BlockchainValidationError(
                "provider_url and contract_address are required without an injected contract"
            )
        Web3 = _load_web3()
        self.web3 = self.web3 or Web3(Web3.HTTPProvider(provider_url))
        if not self.web3.is_connected():
            raise BlockchainError("could not connect to blockchain provider")
        checksum_address = self.web3.to_checksum_address(contract_address)
        self.contract = self.web3.eth.contract(address=checksum_address, abi=self.abi)
        if private_key:
            self.account = self.web3.eth.account.from_key(private_key).address
        if not self.account:
            raise BlockchainValidationError("private_key or account is required for blockchain operations")
        self.account = self.web3.to_checksum_address(self.account)

    def _sender(self, sender: Optional[str]) -> str:
        value = sender or self.account
        if not value:
            raise BlockchainValidationError("sender/account is required for a transaction")
        return validate_address(value)

    def _send(self, function: Any, sender: Optional[str] = None) -> Any:
        account = self._sender(sender)
        try:
            if hasattr(function, "transact"):
                tx_hash = function.transact({"from": account})
            else:
                if self.web3 is None or not self.private_key:
                    raise BlockchainError("signed transaction requires web3 and private_key")
                nonce = self.web3.eth.get_transaction_count(account)
                tx = function.build_transaction(
                    {
                        "from": account,
                        "nonce": nonce,
                        "chainId": self.web3.eth.chain_id,
                    }
                )
                signed = self.web3.eth.account.sign_transaction(tx, self.private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed.raw_transaction)
            if self.web3 is not None and hasattr(self.web3.eth, "wait_for_transaction_receipt"):
                return self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash
        except BlockchainError:
            raise
        except Exception as error:
            raise BlockchainError("blockchain transaction failed") from error

    def register_record(
        self,
        record_id: str,
        storage_reference: str,
        file_hash: str | bytes,
        *,
        sender: Optional[str] = None,
    ) -> Any:
        if not isinstance(record_id, str) or not record_id.strip():
            raise BlockchainValidationError("record_id must be a non-empty string")
        if not isinstance(storage_reference, str) or not storage_reference.strip():
            raise BlockchainValidationError("storage_reference must be a non-empty string")
        digest = normalize_file_hash(file_hash)
        function = self.contract.functions.registerRecord(record_id, storage_reference, digest)
        return self._send(function, sender)

    def grant_access(self, record_id: str, doctor_address: str, *, sender: Optional[str] = None) -> Any:
        if not isinstance(record_id, str) or not record_id.strip():
            raise BlockchainValidationError("record_id must be a non-empty string")
        doctor = validate_address(doctor_address)
        return self._send(self.contract.functions.grantAccess(record_id, doctor), sender)

    def revoke_access(self, record_id: str, doctor_address: str, *, sender: Optional[str] = None) -> Any:
        if not isinstance(record_id, str) or not record_id.strip():
            raise BlockchainValidationError("record_id must be a non-empty string")
        doctor = validate_address(doctor_address)
        return self._send(self.contract.functions.revokeAccess(record_id, doctor), sender)

    def check_access(self, record_id: str, doctor_address: str) -> bool:
        if not isinstance(record_id, str) or not record_id.strip():
            raise BlockchainValidationError("record_id must be a non-empty string")
        doctor = validate_address(doctor_address)
        try:
            return bool(self.contract.functions.canAccess(record_id, doctor).call())
        except Exception as error:
            raise BlockchainError("blockchain access check failed") from error

    def get_record_metadata(self, record_id: str) -> tuple[str, bytes, str]:
        if not isinstance(record_id, str) or not record_id.strip():
            raise BlockchainValidationError("record_id must be a non-empty string")
        try:
            storage_reference, file_hash, registered_by = self.contract.functions.getRecordMetadata(record_id).call()
        except Exception as error:
            raise BlockchainError("blockchain metadata lookup failed") from error
        if isinstance(file_hash, str):
            file_hash = normalize_file_hash(file_hash)
        return str(storage_reference), bytes(file_hash), str(registered_by)

    def record_access(self, record_id: str, *, sender: Optional[str] = None) -> Any:
        if not isinstance(record_id, str) or not record_id.strip():
            raise BlockchainValidationError("record_id must be a non-empty string")
        return self._send(self.contract.functions.recordAccess(record_id), sender)
