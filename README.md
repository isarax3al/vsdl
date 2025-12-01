# VSDL - Verifiable Smart Delegation Links

> A Theoretical Framework for Privacy-Preserving E-Government Delegation with Working Implementation

## Overview

This repository contains both the **research paper** and a **working implementation** of Verifiable Smart Delegation Links (VSDL) - a cryptographic framework for privacy-preserving delegation in e-government systems.

## Repository Structure

```
vsdl/
├── paper/                          # Research Paper
│   ├── VSDL_Paper.tex             # LaTeX source
│   └── VSDL_Paper.pdf             # Compiled PDF
│
├── implementation/                 # Working Implementation
│   ├── server.js                  # Express server with web UI
│   ├── pedersen.js                # Pedersen commitment cryptography
│   └── package.json               # Node.js dependencies
│
└── README.md                      # This file
```

## The Problem

When citizens need help with government portals, they often share their login credentials. This exposes **all** personal data to helpers - even data unrelated to the task at hand.

**Example:** An elderly parent shares their password for ID renewal. The helper can now see financial records, medical history, property registrations - everything.

## The Solution

VSDL enables:
- **Task-specific delegation** - Owner creates a link for a specific task only
- **Field-level privacy** - Only relevant fields are visible to the delegate
- **Cryptographic verification** - Delegate can verify the server filtered data correctly

## Mathematical Foundation

### Pedersen Commitment
```
C = g^m · h^r
```

### Verification Equation
```
C_D = C_H · C_F
```
Where:
- `C_D` = Full record commitment
- `C_H` = Hidden fields commitment  
- `C_F` = Filtered (visible) fields commitment

**If equation holds → Server filtered correctly**

## Quick Start (Implementation)

```bash
cd implementation
npm install
node server.js
# Open http://localhost:3000
```

## Paper

The research paper presents:
- Theoretical framework design
- Cryptographic construction using Pedersen commitments
- Security analysis and definitions
- Limitations and future work

**Citation:**
```
Sarah Abdullah Almehmadi, "Verifiable Smart Delegation Links: A Theoretical 
Framework for Privacy-Preserving E-Government Delegation," 2024.
```

## Paper-to-Code Mapping

| Paper Section | Concept | Code Location |
|---------------|---------|---------------|
| Section 4.1 Definition 2 | Field Commitment | `pedersen.js` - `commitField()` |
| Section 4.1 Definition 3 | Record Commitment | `pedersen.js` - `commitRecord()` |
| Section 4.3 | Verification Equation | `pedersen.js` - `verifyPartition()` |
| Section 3.4 | Token structure (JWT) | `server.js` - JWT payload |
| Algorithm 1 | Verification procedure | `server.js` - `/api/verify` |

## Disclaimer

This is a **proof of concept** for academic demonstration. The implementation is NOT production-ready and lacks:
- Production security hardening
- Persistent storage
- User authentication
- Rate limiting

## References

1. Pedersen, T.P. (1991). "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991, pp. 129-140.

2. Lassak, L., Pan, E., Ur, B., and Golla, M. (2024). "Why aren't we using passkeys?" USENIX Security 2024, pp. 7231-7248.

3. EU Regulation 2024/1183 - European Digital Identity Framework (eIDAS 2.0)

## License

MIT License

## Author

**Sarah Abdullah Almehmadi**  
Email: sarahabdalmehmadi@gmail.com

---

*This repository accompanies the VSDL research paper demonstrating that the theoretical framework is practically implementable.*
