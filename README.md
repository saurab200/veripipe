# VeriPipe: Agentic SQL & Data Quality Firewall

A deterministic SQL proxy, AST validator, and evaluation harness that prevents LLM agents from executing hallucinated columns, invalid joins, or destructive queries against PostgreSQL and Supabase databases.

Author: Avon Budhathoki (jtq19@txstate.edu)

## Overview

```
[AI Agent / LLM] ---> Generated SQL ---> [VeriPipe Proxy] ---> Validated AST ---> [PostgreSQL / Supabase]
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                           [Schema Validator]      [Audit & Metrics]
                           - Table/Col Whitelist   - Query Latency
                           - Destructive Block     - Error Telemetry
```

## Features

- **Schema-Aware AST Parsing**: Uses SQLGlot to parse incoming SQL queries into an Abstract Syntax Tree (AST), checking every table and column against live PostgreSQL information schemas.
- **Hallucination Blocking**: Intercepts non-existent table references, malformed joins, and type mismatches before they hit the database.
- **Safety Enforcement**: Enforces read-only permissions, mandatory LIMIT clauses, and blocks dangerous DDL/DML statements (`DROP`, `ALTER`, `TRUNCATE`).
- **Telemetry & Evals**: Tracks agent query accuracy, execution time, and blocked error signatures.

## Quickstart

```bash
git clone https://github.com/saurab200/veripipe.git
cd veripipe
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m veripipe.proxy
```
