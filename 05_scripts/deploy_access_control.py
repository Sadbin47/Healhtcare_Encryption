"""Deploy AccessControl from a standard Solidity compiler artifact.

Expected artifact shape: ``{"abi": [...], "bytecode": "0x..."}``.
The private key is read from an environment variable and is never written to
disk or included in command-line arguments.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy the AccessControl contract")
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--private-key-env", default="ANVIL_DEPLOYER_PRIVATE_KEY")
    args = parser.parse_args()

    try:
        from web3 import Web3
    except ImportError as error:  # pragma: no cover - environment dependent.
        raise SystemExit("Install requirements.txt before deploying") from error

    private_key = os.environ.get(args.private_key_env, "")
    if not private_key:
        raise SystemExit(f"{args.private_key_env} is not set")
    artifact = json.loads(args.artifact.read_text(encoding="utf-8"))
    abi = artifact.get("abi")
    bytecode = artifact.get("bytecode")
    if not isinstance(abi, list) or not isinstance(bytecode, str) or not bytecode.startswith("0x"):
        raise SystemExit("artifact must contain an ABI list and 0x-prefixed bytecode")

    web3 = Web3(Web3.HTTPProvider(args.rpc_url))
    if not web3.is_connected():
        raise SystemExit("could not connect to RPC provider")
    account = web3.eth.account.from_key(private_key)
    factory = web3.eth.contract(abi=abi, bytecode=bytecode)
    transaction = factory.constructor().build_transaction(
        {
            "from": account.address,
            "nonce": web3.eth.get_transaction_count(account.address),
            "chainId": web3.eth.chain_id,
        }
    )
    signed = account.sign_transaction(transaction)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print(json.dumps({"contract_address": receipt.contractAddress, "transaction_hash": tx_hash.hex()}))


if __name__ == "__main__":
    main()
