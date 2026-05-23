# cloud-pqc-migrator

An agentic Post-Quantum Cryptography (PQC) Migration Engine for AWS and GCP cloud infrastructure.

The tool autonomously discovers every cryptographically-bounded resource in your cloud environment, evaluates it against the finalized NIST PQC standards (FIPS 203/204/205) and CNSA 2.0 mandates, generates precise CLI remediation commands via the Claude AI API, and enforces a strict human-in-the-loop approval gate before any change is executed.

---

## Why this exists

Quantum computers capable of breaking RSA and ECC asymmetric cryptography (Q-Day) are forecast by 2029–2030. The "Harvest Now, Decrypt Later" threat means adversaries are capturing encrypted traffic today to decrypt it once quantum hardware is available. The window to migrate is open now — CNSA 2.0 mandates critical systems be compliant by 2030.

This tool automates the discovery, analysis, and remediation planning required to execute that migration across AWS and GCP environments.

### Standards enforced

| Standard | Algorithm | Purpose |
|---|---|---|
| **FIPS 203** | ML-KEM (CRYSTALS-Kyber) | Key encapsulation / key exchange — replaces RSA/ECDH |
| **FIPS 204** | ML-DSA (CRYSTALS-Dilithium) | Digital signatures — replaces RSA/ECDSA |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Stateless hash-based signatures — secondary defense |

TLS 1.3 is enforced as a hard prerequisite across all edge resources because it is the only protocol capable of negotiating hybrid PQC cipher suites.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Ephemeral Authentication                                    │
│     Ingests AWS/GCP tokens into memory — never written to disk  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Cloud Shell Emulator Loop (Discovery)                       │
│     Runs native aws / gcloud CLI commands, builds CBoM JSON     │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. PQC Compliance Triage Engine                                │
│     Evaluates FIPS 203/204/205 alignment, prioritises gaps      │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Just-in-Time Remediator (Claude AI)                         │
│     Generates target CLI commands + Terraform IaC patches       │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Consensus-Driven Execution Gate                             │
│     Human approval per change, auto-rollback on health failure  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Requirements

- Python 3.11 or newer
- An [Anthropic API key](https://console.anthropic.com/) (for remediation generation)
- For live scans: the [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and/or [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and on `$PATH`
- For dry-run mode: no cloud tools or credentials required

---

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd cloud-pqc-migrator

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Install the package
pip install -e .

# Verify
cloud-pqc-migrator --version
```

---

## Quick Start

### Dry-run mode (no cloud access required)

The fastest way to see the tool in action. It uses realistic mock cloud data for discovery and the real Claude API for remediation generation:

```bash
export ANTHROPIC_API_KEY=sk-ant-...

# Full pipeline: discover → triage → generate remediations → approval gate
cloud-pqc-migrator scan --provider aws --dry-run

# Stop before the LLM step (no API key needed)
cloud-pqc-migrator scan --provider aws --dry-run --skip-execution
```

### Live AWS scan

```bash
export ANTHROPIC_API_KEY=sk-ant-...

cloud-pqc-migrator scan --provider aws
```

You will be prompted to choose an authentication mode:

```
[AWS Authentication]
Choose credential mode:
  1) Role ARN + External ID (STS AssumeRole)
  2) Direct Access/Secret/Session tokens
Mode [2]:
```

### Live GCP scan

```bash
export ANTHROPIC_API_KEY=sk-ant-...

cloud-pqc-migrator scan --provider gcp
```

You will be prompted to choose:

```
[GCP Authentication]
Choose credential mode:
  1) OAuth 2.0 access token
  2) Service account JSON key
Mode [1]:
```

---

## Commands

### `scan`

The primary command. Runs the full 5-module pipeline.

```
cloud-pqc-migrator scan [OPTIONS]

Options:
  --provider [aws|gcp]      Cloud provider to scan.  [required]
  --dry-run                 Use mock data; display but do not execute remediations.
  --output-cbom PATH        Write the discovered CBoM JSON to a file.
  --skip-execution          Stop before remediation generation (discovery + triage only).
  --t-cover-months INTEGER  Data sensitivity window in months for T_start.  [default: 24]
  --t-proj-months INTEGER   Estimated migration project duration in months.  [default: 6]
  --max-remediations N      Cap LLM calls per session (for large environments).
```

**Example — export CBoM for later use:**

```bash
cloud-pqc-migrator scan --provider aws --dry-run \
  --output-cbom cbom-2026-05.json \
  --skip-execution
```

**Example — tighten the timeline calculation:**

```bash
# T_start = 2030-01-01 − 36 months (cover) − 12 months (project) = 2027-01-01
cloud-pqc-migrator scan --provider aws \
  --t-cover-months 36 \
  --t-proj-months 12
```

---

### `triage-only`

Evaluate an existing CBoM file without connecting to any cloud provider. Useful for re-running analysis, sharing findings, or running in CI.

```
cloud-pqc-migrator triage-only CBOM_FILE [OPTIONS]

Options:
  --t-proj-months INTEGER   Estimated project duration in months.  [default: 6]
```

```bash
cloud-pqc-migrator triage-only cbom-2026-05.json
```

---

### `remediate-only`

Generate AI remediation proposals from an existing CBoM without executing them. Outputs the full approval panel view for every gap, useful for asynchronous review.

```
cloud-pqc-migrator remediate-only CBOM_FILE [OPTIONS]

Options:
  --max-remediations N      Cap the number of LLM calls.
```

```bash
ANTHROPIC_API_KEY=sk-ant-... cloud-pqc-migrator remediate-only cbom-2026-05.json
```

---

## Authentication Details

### AWS

**Mode 1 — STS AssumeRole (recommended for production)**

Provide a Role ARN and optional External ID. The tool calls `aws sts assume-role` and stores the resulting ephemeral STS token trio (`ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `SESSION_TOKEN`) in memory for the duration of the session. Tokens are automatically refreshed if they are within 5 minutes of expiry.

Minimum IAM permissions the role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeSSLPolicies",
        "cloudfront:ListDistributions",
        "cloudfront:GetDistributionConfig",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "kms:ListKeys",
        "kms:DescribeKey",
        "apigateway:GET",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Add `elasticloadbalancing:ModifyListener`, `cloudfront:UpdateDistribution`, etc. if you intend to execute remediations (not just generate them).

**Mode 2 — Direct tokens**

Paste your `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN` directly. Input is hidden via `getpass`.

### GCP

**Mode 1 — OAuth 2.0 access token**

Obtain a short-lived token via `gcloud auth print-access-token` in another terminal and paste it when prompted.

**Mode 2 — Service account JSON key**

Paste the full JSON content of a service account key file. The content is held in a temporary in-memory file and deleted from disk immediately after the session clears.

Minimum roles needed on the service account:

- `roles/compute.networkViewer`
- `roles/certificatemanager.viewer`
- `roles/cloudkms.viewer`
- `roles/iam.securityReviewer`

---

## The Gap Priority System

Gaps are classified into three priority tiers based on the F5 migration priority matrix:

| Priority | Label | Criteria |
|---|---|---|
| **1 — CRITICAL** | Legacy Deficiency | Asset cannot negotiate TLS 1.3 at all, or uses deprecated ciphers (RC4, 3DES, AES-CBC-SHA). Zero crypto-agility. |
| **2 — HIGH** | Ingress & Data | Internet-facing assets (CloudFront, ALBs, API Gateway) with TLS 1.2 maximum. Subject to Harvest-Now-Decrypt-Later interception. |
| **3 — MEDIUM** | Perimeter & Core | Internal PKI, KMS signing keys, VPN tunnels, IAM signing infrastructure. |

### T_start Deadline Formula

For each gap the tool computes the latest date by which your migration must begin:

```
T_start = T_q-day − T_cover − T_proj
```

Where:
- `T_q-day` = 2030-01-01 (CNSA 2.0 hard deadline)
- `T_cover` = data sensitivity window (default: 24 months for internet-facing, 12 months internal)
- `T_proj` = your migration project duration (default: 6 months, override with `--t-proj-months`)

A gap on an internet-facing resource with default settings produces a T_start of **2027-07-01** — you should have started already or be starting now.

---

## What gets discovered

### AWS resources

| Resource | CLI Command | What is assessed |
|---|---|---|
| ALB/NLB Listeners | `aws elbv2 describe-listeners` | SSL policy name → TLS version + cipher tier |
| CloudFront Distributions | `aws cloudfront list-distributions` | `MinimumProtocolVersion` field |
| ACM Certificates | `aws acm list-certificates` | `KeyAlgorithm`, expiry date |
| KMS Keys | `aws kms describe-key` | `KeySpec` (RSA_2048, EC_prime256v1, etc.) |
| API Gateway Domains | `aws apigateway get-domain-names` | `SecurityPolicy` (TLS_1_0, TLS_1_2) |

### GCP resources

| Resource | CLI Command | What is assessed |
|---|---|---|
| SSL Policies | `gcloud compute ssl-policies list` | `minTlsVersion`, enabled cipher features |
| Certificate Manager Certs | `gcloud certificate-manager certificates list` | Certificate scope and metadata |
| KMS Keys | `gcloud kms keys list` | `algorithm` field (RSA_DECRYPT_OAEP_*, etc.) |
| Target HTTPS Proxies | `gcloud compute target-https-proxies list` | Associated SSL policy reference |

---

## The Approval Gate

Every remediation proposal is presented in a Rich terminal panel before anything is executed:

```
╭─ REMEDIATION PROPOSAL [1/7] — Priority 1: CRITICAL  [DRY RUN] ──────────────╮
│  Resource ID    │  arn:aws:elasticloadbalancing:us-east-1:123:listener/...   │
│  Resource Kind  │  alb_listener                                              │
│  Provider       │  AWS                                                       │
│  Internet-Facing│  Yes                                                       │
│ ─────────────── ┼──────────────────────────────────────────────────────── │
│  Gap            │  Listener enforces max TLS 1.2; TLS 1.3 required for PQC  │
│  FIPS Violations│  FIPS_203                                                  │
│  Deadline       │  Start by 2027-07-01                                       │
│ ─────────────── ┼──────────────────────────────────────────────────────── │
│  Current State  │  TLS 1.2 only; cipher policy: ELBSecurityPolicy-2016-08   │
│  Target State   │  TLS 1.3 + hybrid ML-KEM-768 (FIPS 203 / CNSA 2.0)       │
│ ─────────────── ┼──────────────────────────────────────────────────────── │
│  Fix Command    │  aws elbv2 modify-listener --listener-arn arn:... \        │
│                 │    --ssl-policy ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06   │
│  Rollback Cmd   │  aws elbv2 modify-listener --listener-arn arn:... \        │
│                 │    --ssl-policy ELBSecurityPolicy-2016-08                  │
│ ─────────────── ┼──────────────────────────────────────────────────────── │
│  Claude's Notes │  Upgrades to ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06     │
│                 │  which enables TLS 1.3 and hybrid ML-KEM-768 per FIPS 203  │
╰───────────────────────────────────────────────────────────────────────────────╯

  [A] Approve and Execute    [S] Skip    [Q] Quit session
```

**Execution flow after approval:**

1. The rollback command is captured into a local variable in memory before the fix command runs.
2. The fix command is executed via subprocess with your credentials injected into the process environment.
3. A health check re-queries the resource and verifies the field changed to the expected value.
4. If the health check fails, the rollback command is automatically executed and the status is set to `ROLLED_BACK`.

No state-altering command runs without an explicit `A` keypress.

---

## CBoM JSON format

The Cryptographic Bill of Materials produced by discovery is a JSON file you can save, share, and re-process:

```json
{
  "scan_timestamp": "2026-05-23T10:00:00+00:00",
  "provider": "aws",
  "account_id": null,
  "dry_run": true,
  "assets": [
    {
      "resource_id": "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/prod-alb/...",
      "resource_kind": "alb_listener",
      "provider": "aws",
      "region": "us-east-1",
      "min_tls_version": "TLS_1_2",
      "cipher_suites": ["ELBSecurityPolicy-2016-08"],
      "is_internet_facing": true,
      "raw_api_response": { ... }
    }
  ],
  "cli_commands_executed": [
    "aws elbv2 describe-load-balancers --output json",
    "aws elbv2 describe-listeners --load-balancer-arn arn:... --output json",
    ...
  ]
}
```

---

## Claude API and Prompt Caching

Module 4 uses the Anthropic `claude-sonnet-4-6` model. The large PQC standards system prompt (~600 tokens) is sent with `cache_control: {"type": "ephemeral"}`. Because all gaps in a session are processed sequentially within the 5-minute cache TTL, every call after the first benefits from a cache hit — reducing input token cost by roughly 90% for large environments.

Set your API key before running:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Use `--max-remediations N` to cap API calls in very large environments while you assess the first N critical findings.

---

## Running tests

```bash
pip install pytest pytest-mock
pytest tests/ -v
```

All 28 tests run without cloud credentials or an Anthropic API key.

---

## Project structure

```
cloud-pqc-migrator/
├── cloud_pqc_migrator/
│   ├── main.py                  # CLI entry point (Click)
│   ├── auth/                    # Ephemeral credential providers
│   ├── discovery/               # Cloud CLI executor + AWS/GCP discovery steps
│   ├── triage/                  # PQC rule engine + timeline calculator
│   ├── remediation/             # Claude API pipeline + output validator
│   ├── execution/               # Approval gate + health check + rollback
│   ├── models/                  # Pydantic data models (CBoM, Gap, Remediation)
│   └── ui/                      # Rich terminal panels and progress bars
├── tests/                       # Unit tests (28 tests, no cloud/API needed)
├── pyproject.toml
└── requirements.txt
```

---

## Security notes

- **Credentials are never written to disk.** AWS tokens are stored only in a Python `dict` and injected into subprocess environment variables. GCP service account JSON is written to a `NamedTemporaryFile` that is immediately overwritten with empty bytes and deleted when the session ends.
- **Generated commands are validated before display.** The validator rejects any LLM output containing shell metacharacters (`;`, `&&`, `||`, backticks) and requires commands to start with `aws ` or `gcloud `.
- **Rollback commands are held in memory.** The rollback string is captured as a local variable in the approval gate before the fix command executes — it is never persisted.
- **No cloud changes happen without explicit approval.** The gate blocks on user input (`A`) for every individual remediation. `--dry-run` mode never calls any cloud CLI.
