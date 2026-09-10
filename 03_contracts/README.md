# AccessControl contract

`AccessControl.sol` is the Phase 5 metadata and consent registry.

It stores only:

- a hashed logical record identifier;
- an encrypted-object CID/reference;
- the SHA-256 hash of the encrypted envelope;
- the registering application/patient address; and
- doctor permission state.

It never stores EHR plaintext, AES keys, ECC/ML-KEM private keys, or encrypted
files. `recordAccess()` emits an on-chain access event after the caller's
permission is checked. The later application service should still perform its
own consent/database checks and envelope integrity verification.

## Local deployment

Use Anvil or Hardhat for a reproducible local chain. Compile the contract with
Solidity `0.8.24` (or a compatible `0.8.x` compiler), deploy the resulting
artifact with `05_scripts/deploy_access_control.py`, and pass its address plus
ABI to `framework/blockchain_client.py`.

The current repository includes the contract and client/test contract, but no
live chain endpoint or deployed address is committed. Never commit a real
private key or production RPC credential.
