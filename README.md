# ZK Age Verification — Minimal Demo (ZoKrates + Solidity)

This repository contains a minimal end-to-end example of **Zero-Knowledge age verification**, showing how to:

- write a simple ZoKrates circuit  
- generate a SNARK proof  
- verify it on-chain through a Solidity verifier  
- integrate the verification into a small “AgeGate” smart contract

Only the essential files used during the workshop are included.

---

## 📁 Files Overview

| File | Description |
|------|-------------|
| **age.zok** | ZoKrates circuit proving that the user is **≥ 18 years old** without revealing their birth year. |
| **proof.json** | Example ZK-SNARK proof generated using ZoKrates. |
| **verifier.sol** | Solidity verifier contract automatically generated via `zokrates export-verifier`. |
| **AgeGate.sol** | Simple contract that uses the verifier to grant access if the proof is valid. |
| **LICENSE** | MIT License for open educational use. |

---

## ▶️ Quick Usage (Remix)

1. Open the Remix IDE  
2. Create two files:  
   - `verifier.sol`  
   - `AgeGate.sol`  
3. Deploy **Verifier**  
4. Deploy **AgeGate** using the Verifier’s address  
5. Open `proof.json` and copy the values into the `enter(...)` function  
6. Call `enter`  
7. If the proof is valid, the contract emits: AccessGranted(msg.sender)

---

## 🛠 Regenerating the Proof (optional)

zokrates compile -i age.zok
zokrates setup
zokrates compute-witness -a <birthYear> <currentYear>
zokrates generate-proof
zokrates export-verifier



## Purpose

This repository accompanies a university workshop on:
	•	practical ZK-SNARKs
	•	ZoKrates tooling
	•	on-chain verification
	•	privacy-preserving smart-contract design

It is intentionally minimal and intended for educational use only.
