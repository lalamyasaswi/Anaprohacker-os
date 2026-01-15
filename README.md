# ProcHacker — AI-Powered Windows Process Analysis Toolkit

ProcHacker is an experimental Windows-based process monitoring and anomaly detection system written in C.  
It combines traditional Windows API telemetry with lightweight machine learning logic to assess process behavior, security risks, and resource usage.

---

## 🚀 Features

- 🔍 **Process Enumeration**
  - Collects PID, PPID, handles, threads, priorities, execution states
  - Uses `CreateToolhelp32Snapshot` & `Process32First/Next`

- 📊 **Resource Profiling**
  - CPU usage estimation
  - Memory and working set monitoring (via `psapi.dll`)
  - Thread and priority metrics

- 🤖 **Machine Learning-Based Anomaly Detection**
  - Custom feature extraction pipeline (`MAX_FEATURES = 50`)
  - Logistic regression style anomaly classifier
  - Deep neural network for behavior scoring

- 🛡 **Security Analysis**
  - Risk scoring based on resource usage & process patterns
  - Flags suspicious or abnormal processes
  - CLI for viewing system risk levels

- 🎛 **Interactive Command Console**
  - `list` → show process table
  - `tree` → process parent hierarchy
  - `monitor <pid>` → detailed metrics
  - `security` → advanced risk analysis
  - `export csv` → export telemetry
  - `kill <pid>` → terminate process

- 📈 **Visualization (CLI-based)**
  - CPU bar charts
  - Memory usage bars

---

## ⚙️ Architecture Overview

ProcHacker is divided into logical components:

| Component | Responsibility |
|---|---|
| `ProcessInfo` | Stores live metrics per process |
| `SystemStats` | Tracks system-wide resource usage |
| `MLModel` | Linear anomaly detector |
| `NeuralNetwork` | Experimental deep model |
| WinAPI Layer | Process enumeration & telemetry |
| CLI Interface | User-facing commands |

---

## 🧠 Machine Learning Notes

ProcHacker includes **experimental** ML components:

### Feature Extraction
Extracted features include:
- PID/PPID logs
- CPU/memory usage normalization
- Thread metrics
- Command line flags
- Heuristic keywords (e.g. `miner`, `crypto`, etc.)

### Models Included
- **Logistic-style anomaly detector**
- **Small feed-forward neural network (DNN)**

📌 These ML components are **not production-grade** — they are for research/demo purposes only.

---

## 🖥 Supported Platform

