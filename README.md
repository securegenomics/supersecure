# SuperSecure

**Computation platform built for secure scientific collaboration & cryptographically verifiable science**

Simplest way of doing privacy-preserving collaborative science. Native for [Fully Homomorphic Encryption (FHE)](https://vitalik.eth.limo/general/2020/07/20/homomorphic.html) and federated computation.

## Manifesto
Privacy-first
- No data leaves local unencrypted
- Server cannot decrypt data

Hyper-shareable
- Research protocols are github-repos
  
Mathematically Verifiable
- Every computation, data, and protocol is a cryptographic artifact


## Computation Protocols
**Multi-party Homomorphic Encryption**
```
protocol-*
|____________ receiver_generate_keys.py
|
|____________ client_compute.py
|____________ client_encrypt.py
|
|____________ server_compute.py
|
|____________ receiver_decrypt.py
|____________ receiver_interpret.py
|
|
|____________ config.yaml
```
e.g. Allele Frequency Analysis, GWAS

**Private Query Homomorphic Encryption**
```
protocol-*
|____________ receiver_generate_keys.py
|____________ receiver_compute.py
|____________ receiver_encrypt.py
|
|____________ client_compute.py
|____________ client_encrypt.py
|____________ client_query.py
|
|____________ receiver_decrypt.py
|____________ receiver_interpret.py
|
|
|____________ config.yaml
```
e.g. Drug discovery company tests its drug target variants on biobank data

**Secure Two-Party Computation (2PC)**
```
protocol-*
|____________ client_1_generate_keys.py
|____________ client_1_compute.py
|____________ client_1_encrypt.py
|
|____________ client_2_generate_keys.py
|____________ client_2_compute.py
|____________ client_2_encrypt.py
|
|____________ server_compute.py
|
|____________ client_1_decrypt.py
|____________ client_1_interpret.py
|
|____________ client_2_decrypt.py
|____________ client_2_interpret.py
|
|____________ config.yaml
```
e.g. Paternal DNA test, where only participants can decrypt the result

**Local Only**
```
protocol-*
|____________ local_compute.py
|____________ config.yaml
```
e.g. Ancestry report on individual genome

**Secure Data Share**


## Flow


Client 1: data -> local compute -> encrypt -> upload to server
Client 2: data -> local compute -> encrypt -> upload to server
..
Server: aggregated encrypted data -> compute -> encrypted result
Receiver: download encrypted result -> decrypt -> interpret


Slides > https://docs.google.com/presentation/d/1SukCLvEXRyfDW0yBySLjkYX7lw88qkNYt8BBJnEOrAM/edit?slide=id.p#slide=id.p


## Other goals
LLM-first
– design API for AI Agents to process easily


## Next

### 🔐 Hash-Based Provenance: Scientific Truth as a Chain of Commitments

Treat **every computation** as a cryptographically signed step:
- Every input dataset has a hash
- Every version of your code has a hash
- Each computation step generates a new hash by combining:
    - Data hash
    - Code hash
    - Config/parameter hash
    - Previous step hash (for lineage)

This results in a **chain of composable, tamper-proof proofs** that describe **exactly** how an output came to be — like Git commits, but across data + code + math.

📌 **Even if you don’t share your input data**, others can **verify** that your output hash is consistent with what it should be, given the hash of your data and your open-source computation protocol. 



---

**Built with ❤️ for privacy-preserving genomic research**

*SecureGenomics CLI v0.1.0 - Making research more collaborative and private*
