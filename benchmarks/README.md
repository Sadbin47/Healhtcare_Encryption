# Phase 11 Benchmarks

These runners measure the locally verified part of the framework using the
same `EHR.csv`, Python process, cryptography library, timer, warm-up count, and
repeat count for both key-protection branches.

```bash
python3 benchmarks/benchmark_crypto.py \
  ../../06_Datasets_and_Data/EHR.csv --repeats 10 --warmups 2

python3 benchmarks/benchmark_workflow.py \
  ../../06_Datasets_and_Data/EHR.csv --repeats 10 --warmups 2
```

Outputs are written to `benchmarks/results/` as JSON summaries and raw CSV
samples. JSON contains source hash, environment, sizes, timing statistics,
and explicit unavailable-live-metric explanations. Plaintext EHR values and
secret keys are not written.

`benchmark_crypto.py` measures AES-256-GCM, ECC-ECDH-P256, and ML-KEM-768
operations. `benchmark_workflow.py` measures upload, local envelope download,
authorization check, and authorized end-to-end retrieval using `LocalStorage`
and `LocalBlockchainDouble`.

The following are intentionally not measured until deployment is configured:
live IPFS, VPS HTTPS, Anvil/Hardhat/provider transactions, TLS network
latency, and WireGuard latency.
