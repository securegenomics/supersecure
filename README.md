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
- Scientific truth as a chain of commitments


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


## Constraints
[bozmen.io/constrains-are-your-friends](https://bozmen.io/constrains-are-your-friends)
- Single protocol language: Python
- Deterministic outputs: no random number generator
- On the server, data goes in/out encrypted and stays always such
- Server can never accept a private key



## Lower priority goals
LLM-first
– results, and API are easy to process for AI Agents
