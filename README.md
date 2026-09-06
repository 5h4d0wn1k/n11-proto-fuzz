# N11 — Protocol Fuzzer

TCP/UDP protocol fuzzing with mutation engine, crash detection, and response analysis.

## Overview

This project implements a network protocol fuzzer that:
- Mutates payloads using multiple strategies (random, boundary, overflow, bitflip, format string)
- Monitors for crashes, timeouts, and anomalous responses
- Supports both TCP and UDP protocol fuzzing
- Fuzzes multiple ports simultaneously
- Logs all mutations and results for analysis

## Features

- **Mutation engine**: 7 strategies including combo mutations
- **Boundary values**: Tests edge cases (0, 0xFF, max sizes)
- **Format string**: Tests for format string vulnerabilities
- **Overflow testing**: Large payloads for buffer overflow detection
- **Bit flipping**: Subtle mutations for protocol logic bugs
- **Crash detection**: Records crashes, timeouts, and anomalies
- **Multi-port**: Fuzz multiple ports in sequence

## Installation

No external dependencies — uses only the Python standard library.

## Usage

```bash
# Fuzz TCP ports
python3 proto_fuzz.py 192.168.1.1 --tcp-ports 21,22,80,443

# Fuzz UDP ports
python3 proto_fuzz.py 192.168.1.1 --udp-ports 53,161,123

# Fuzz both with custom iterations and save results
python3 proto_fuzz.py 192.168.1.1 --tcp-ports 80 --udp-ports 53 \
    --iterations 200 --output results.json

# Use specific strategies
python3 proto_fuzz.py 192.168.1.1 --tcp-ports 22 \
    --strategies boundary,overflow,format
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N11 — Protocol Fuzzer             ║
╚═══════════════════════════════════════╝
Target: 192.168.1.1

[*] TCP Fuzzing 192.168.1.1:22
    Iterations: 100
    Strategies: ['random', 'boundary', 'overflow', 'bitflip', 'format', 'combo']
    [25/100] completed
    [50/100] completed
    [75/100] completed
    [100/100] completed

==================================================
  CRASH DETECTOR SUMMARY
==================================================
  Total tests:   100
  Crashes:       0
  Timeouts:      3
  Anomalies:     1
  Connections:   96
==================================================
```

## Tests

Deterministic, offline, no external services beyond loopback:

```bash
python3 -m unittest discover -s tests -v
```

## Offline Demo

```bash
cd firmware
python3 proto_fuzz.py --demo    # exit 0 fast (finds the planted bug)
python3 proto_fuzz.py --help
```

The demo spins up the stdlib `dummy_proto_server` on `127.0.0.1`, runs the
fuzzer, and automatically discovers the crashing input (a `type=3` packet
missing its 8-byte signature trailer). Non-loopback targets are rejected.

## Live Lab Test Plan

Performed against a **self-hosted, isolated lab service** only, on the
loopback/`127.0.0.1` or an authenticated lab VLAN with documented
placeholder addresses. Never fuzz third-party services.

1. **Stand up a stub service** — run the loopback dummy server or an
   authorized lab test service on an ephemeral localhost port.
2. **Probe valid traffic** — `python3 proto_fuzz.py --host 127.0.0.1 --port <p> --iterations 10`
   to confirm a baseline of `OK`/`ERR` responses and no spurious crashes.
3. **Fuzz** — run with increasing `--iterations` until a crash input is found.
4. **Triage** — record `payload_hex` from the crash entry, replay it against
   the paused service, and confirm the parser raises.
5. **Clean exit codes** — `0` when a crash is discovered, `1` when none is
   found within the probe budget.
6. **Cleanup** — terminate the stub service and confirm no threads/ports remain.

## Metrics

- Probes-to-first-crash: number of inputs sent before the first crash is found.
- Crash payload size: bytes of the minimal reproducible crashing input.
- False crashes: inputs classified as crashes that replay benignly.
- Coverage proxies: distinct types/lengths touched before discovery.
- Runtime: wall-clock time to first crash (should be sub-second for the demo).

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
