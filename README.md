# SubRecon

### Advanced Subdomain Reconnaissance & Website Asset Discovery Tool

SubRecon is a Python-based command-line framework designed to organize authorized subdomain reconnaissance and website asset discovery into one unified workflow.

It integrates existing reconnaissance utilities, manages scan results using SQLite, and generates structured reports through a clean terminal interface.

## Features

- Passive subdomain discovery.
- DNS record resolution.
- Website asset organization.
- Basic technology information storage.
- SQLite-based result management.
- Scan history and result retrieval.
- JSON, CSV, TXT and HTML report exports.
- Integrated tool availability checks.
- Scope enforcement and authorization safeguards.

## Integrated Tools

| Tool | Purpose |
|---|---|
| Subfinder | Passive subdomain discovery |
| Amass | Passive subdomain discovery |
| DNSx | DNS resolution |

Additional utilities, including Katana, Nuclei and ProjectDiscovery HTTPx, may be detected by the availability checker. Detection does not mean they are integrated into the execution workflow.

## Technology Stack

- Python 3.11+
- Typer
- Rich
- SQLite
- Pytest

## Supported Platforms

- Kali Linux
- Ubuntu
- Debian

Termux compatibility is a development consideration. Full compatibility has not yet been established.

## Installation

Clone the repository:

```bash
git clone https://github.com/dhananjaykdanish-creator/SubRecon.git
cd SubRecon
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install SubRecon:

```bash
python -m pip install -e .
```

Install and configure the supported external reconnaissance tools separately.

## Usage

Check the command-line interface:

```bash
subrecon --help
```

Check external tool availability:

```bash
subrecon check
```

Explore available commands:

```bash
subrecon scan --help
subrecon history --help
subrecon results --help
subrecon export --help
```

## Project Architecture

SubRecon is organized into modular components:

- `commands/` — CLI commands.
- `core/` — Core models, normalization and scope enforcement.
- `integrations/` — External tool adapters.
- `modules/` — Discovery workflows.
- `reporting/` — Report generation.
- `storage/` — SQLite database and repositories.
- `tests/` — Automated tests.

## Development and Testing

Run the test suite:

```bash
pytest -v
```

Build distribution packages:

```bash
python -m build
```

## Security and Responsible Use

SubRecon is intended exclusively for authorized security assessments and educational purposes.

- Only assess domains and assets for which you have explicit permission.
- Respect defined assessment scope and applicable laws.
- Passive reconnaissance is the default approach.
- Do not use the project for unauthorized access, exploitation, credential attacks, or disruptive activity.

Users are responsible for ensuring that their activities are authorized.

## Development Status

SubRecon is under active development.

The current implementation includes core discovery integrations, DNS resolution, SQLite storage, CLI commands, report exports and automated tests.

## License

A license has not yet been selected. Until one is added, the project should not be assumed to grant permission for redistribution or modification.
