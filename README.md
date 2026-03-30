# 🛡️ Enterprise Quantum-Proof Asset Scanner
**PNB CyberSecurity Hackathon 2026 Submission**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Framework-FF4B4B)
![Plotly](https://img.shields.io/badge/Plotly-Interactive_Data-3F4F75)
![Cryptography](https://img.shields.io/badge/Security-X.509_Parsing-green)

## Problem Statement
Modern financial institutions rely on TLS and RSA/ECC encryption to secure data. However, the impending threat of quantum computing (Shor's Algorithm) renders current cryptographic standards vulnerable ("Harvest Now, Decrypt Later"). Organizations currently lack visibility into their cryptographic blast radius and post-quantum readiness.

## Our Solution
An agentless, multi-threaded DevSecOps scanning engine that maps an organization's cryptographic attack surface. It calculates a proprietary **Quantum Vulnerability Index (QVI)** for every asset and provides an interactive dashboard for executive visibility.

### Key Features
* **Multi-Threaded Discovery:** Concurrently scans domains, APIs, and `/24` CIDR blocks.
* **Deep Crypto Analysis:** Extracts X.509 certificates, ALPN (HTTP/2), and cipher suites using raw socket connections.
* **QVI Scoring Engine:** Algorithmically grades assets (Tier-1 Elite to Critical Risk) based on NIST post-quantum recommendations (e.g., Kyber/ML-KEM readiness).
* **Quantum Attack Surface Map:** An interactive, drill-down Plotly Treemap visualizing the exact blast radius of vulnerable protocols.
* **CBOM Export:** One-click generation of a Cryptographic Bill of Materials (JSON/CSV) for CERT-In compliance and SIEM integration.

---

## Architecture (Two-Tier)

**Tier 1: Presentation Layer**
* **Streamlit UI:** Hosts the Executive Dashboard, Deep Analysis Scanner, and CBOM Export modules.
* **Plotly Engine:** Renders the dynamic Attack Surface Treemap.

**Tier 2: Logic & Network Layer**
* **Thread Pool Manager:** Dispatches asynchronous network probes.
* **TLS / Network Probe:** Executes raw TCP/TLS handshakes without requiring agents.
* **X.509 Parser:** Utilizes Python's `cryptography` library to extract key algorithms and SANs.

---

## ⚙️ Installation & Quick Start

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/sagar-16rs/QUANTUM-SCANNER.git]
   cd quantum-scanner
   ```

2. **Install the required dependencies:**
   ```bash
   pip install streamlit pandas plotly cryptography
   ```
3. **Launch the Enterprise Dashboard:**
   ```bash
   python -m streamlit run app.py
   ```
