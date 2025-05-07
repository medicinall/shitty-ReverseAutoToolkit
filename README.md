#  ReverseAutoToolkit

**ReverseAutoToolkit** is a lightweight and experimental reverse engineering automation script built with Python and Radare2 (`r2pipe`). Its purpose is to assist in the rapid triage of binary executables, making it easier to extract and analyze information like strings, encoded data, and function behaviors — all without needing a full GUI RE environment.

> ⚠️ This toolkit is intentionally minimal and exploratory. It’s meant for quick insights, not full decompilation or production-grade analysis.

---

## Features & Utilities

ReverseAutoToolkit provides the following utilities:

- **Radare2 integration** via `r2pipe` for automated static analysis
- **String extraction** from within the binary
- **Encoded data detection** (Base64, ROT13, XOR heuristics)
- **Function scanning** to identify and dump suspicious or unique logic
- **Prints output** in human-readable format for reverse engineers and CTF solvers
- **Basic decoding attempts** on suspicious-looking string content

---

## 🔧 Requirements

Before using this toolkit, make sure the following tools and libraries are installed:

### ✅ Dependencies

- **Python 3.7+**
- **[Radare2](https://rada.re/n/)** (must be in your PATH)
- **Python module `r2pipe`**

To install the required Python module:

```bash
pip install r2pipe
