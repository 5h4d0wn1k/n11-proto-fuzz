> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N11 — Protocol Fuzzer

Loopback network protocol fuzzer for robustness testing and crash discovery — mutates malformed
TCP payloads against a local service, detects crashes and timeouts, and records the exact crashing
input. Standard library only, offline by default.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/n11-proto-fuzz)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n11-proto-fuzz)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/n11-proto-fuzz)

## Why

Protocol fuzzing finds robustness bugs that unit tests miss: truncated trailers, boundary lengths,
and malformed type fields. N11 demonstrates the fuzzing loop end-to-end — a deterministic corpus
mixed with biased random mutations is sent to a TCP service until a crash input is discovered, at
which point the crashing `payload_hex` is recorded so you can replay and triage it. It is an
educational network-security and robustness-testing tool, and it is designed to run against
loopback/`127.0.0.1` or an authorized lab service only — never a third-party host.

## Features

- **Crash discovery** — hunts for inputs that drop the connection or reset on parse; records
  crash, timeout, and OK outcomes per probe.
- **Deterministic corpus** — valid headers, boundary values, and the planted crash-inducing case
  (`type=3` with a short missing trailer).
- **Biased mutation** — seeded RNG explores the crash-prone `type=3` space too.
- **Local demo server** — `firmware/dummy_proto_server.py` spins up a stdlib loopback service with a
  planted bug.
- **Clean exit contract** — `0` when a crash is discovered, `1` when the probe budget is spent.

## Quickstart

Prerequisite: Python 3 (standard library only).

```bash
python3 firmware/proto_fuzz.py --help
python3 firmware/proto_fuzz.py --demo            # spin up loopback server, find the planted bug
python3 firmware/proto_fuzz.py --host 127.0.0.1 --port 9000 --iterations 200
python3 firmware/proto_fuzz.py --host 127.0.0.1 --port 9000 --iterations 100 --timeout 0.5
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

- `firmware/proto_fuzz.py` — fuzzer, crash detector, and CLI.
- `firmware/dummy_proto_server.py` — the loopback stub service used by the demo.
- `tests/` — stdlib unittest suite.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep experiments loopback-only and the sampler reproducible.

## License

MIT — see [LICENSE](LICENSE).