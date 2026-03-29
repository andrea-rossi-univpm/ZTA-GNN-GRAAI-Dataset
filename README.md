# Zero Trust Cyber-Range Dataset Generation

Multi-layer, labeled event dataset for Zero Trust Architecture (ZTA) research, covering the full network stack from Layer 2 ARP events to application-level JWT audit records. Generated within an isolated Hyper-V cyber range and collected via Splunk Enterprise with over 60 sourcetypes.

## Motivation

Existing intrusion-detection corpora (NSL-KDD, CICIDS, UNSW-NB15, etc.) target packet-level anomaly detection in perimeter-based security models, a fundamentally different problem from the **continuous, context-aware trust evaluation** required by Zero Trust. To the best of our knowledge, no publicly available dataset captures the multi-layer, correlated access events that a dynamic Policy Decision Point (**PDP**) needs: identity context (JWT claims, session state), device context (browser fingerprint, X.509 certificates), network context (passive OS fingerprinting, ARP monitoring), and resource context (request routes, CRUD operations) — all labeled with ground-truth suspicious/benign flags.

This dataset fills that gap.

## Research Context

The dataset was produced as a joint effort across two M.Sc. theses at **Università Politecnica delle Marche** (A.Y. 2024–2025), under the supervision of Prof. Luca Spalazzi and Dr. Gianluca Bonifazi:

**The first thesis constructed the range and generated the data; the second thesis used this data to train and evaluate the GNN-based PDP.**

## Infrastructure Overview

The cyber range runs on Microsoft Hyper-V, partitioned into three isolated security tiers enforced by a dual-homed Next-Generation Firewall (OPNsense + Zenarmor DPI):

1. **Physical Host** — Windows 11 with Hyper-V, Internet-connected via NAT.
2. **Internal Network** (192.168.2.0/24) — Firewall-mediated Internet access.
3. **Private Isolated Network** (192.168.3.0/24) — Production services, monitoring probe, client endpoints. All external traffic passes through firewall inspection.

A passive network probe on a dedicated Ubuntu LTS VM runs four open-source services in promiscuous mode: **Snort 2.9** (signature-based IDS), **tcpdump** (full-packet forensic capture), **p0f** (passive OS fingerprinting via TCP/IP stack analysis), and **ARPwatch** (Layer 2 ARP-spoofing detection).

The **Blazor WebAssembly SPA** (.NET 10) serves as the primary data-collection focal point: every HTTP request traverses two mandatory middleware interceptors that verify JWT signature and live server-side session, then triggers a six-phase enrichment pipeline extracting HTTP metadata, JWT claims, browser fingerprint HMAC (~30 device characteristics), suspicious-activity flags, and SHA-256 integrity hash before synchronous forwarding to Splunk.

All events converge in **Splunk Enterprise** through a taxonomy of over 60 sourcetypes, each carrying SHA-256 integrity and HMAC-SHA256 authentication signatures.

## Dataset Generation

Two separated traffic streams are injected into the running infrastructure:

**Legitimate traffic** — A Python bot authenticates against the Blazor application and executes randomized CRUD sequences across all entities, running the client-side fingerprinting module to produce genuine browser-fingerprint headers. All records are labeled `Suspicious = false`.

**Malicious traffic** — A modular penetration-testing suite on a dual-homed Kali Linux node covers the full kill chain: ARP poisoning/flood, TLS downgrade and three-layer MitM with JSON tampering, JWT manipulation (signature bypass, algorithm confusion, claim injection, JKU/X5C/X5U injection, KID injection), SQL injection and privilege escalation, and high-volume application fuzzing with honeypot triggering. All records are labeled `Suspicious = true`.

Cross-layer consistency is the primary discriminating feature for trust scoring — e.g., a Linux TCP/IP stack signature observed by p0f on an IP whose JWT claims a Windows workstation triggers a trust reduction and automatic session revocation.

## File Inventory

| File | SHA-256 | Size | Description |
|------|---------|------|-------------|
| `export_22Dec2025_010633.csv` | `cce55ca294323909a5ea8f99e97d581ebae74d9964999d58e0f466a21747cc1d` | 838.1 MB | Raw Splunk export, 347,768 events |
|  [`export_22Dec2025_010633.csv.7z`](./CSV_Inventory/Golden_Sample_CSV/export_22Dec2025_010633.csv.7z)  | `9e7a5995797e3310a00a7684047ea298002328819599c65831b6d30c5d81d5f0` | 24.1 MB | 7-Zip compressed archive of the CSV (using ULTRA compression), achieving a 97% reduction in size. |

### CSV Schema

Each row corresponds to a single Splunk event with the following columns:

| Column | Description |
|--------|-------------|
| `time` | Event timestamp |
| `host` | Originating machine identifier |
| `source` | Application or component that produced the event |
| `sourcetype` | Splunk sourcetype classification (60+ types) |
| `message` | JSON-encoded event body with structured fields varying by sourcetype |

The `message` field contains sourcetype-specific structured data. For Blazor audit events this includes fields such as `Id`, `User`, `IP`, `UserAgent`, `EventType`, `Suspicious`, `HTTPStatusCode`, `ResourceContext`, `ClientCertificate`, `UserContext`, `HashCheck`, and more.

## Dataset Composition

The balanced dataset contains **347,768** events: **207,131** benign and **140,637** suspicious.

| Traffic Class | Events | Suspicious | Not Suspicious | Duration |
|---|---:|---:|---:|---|
| CRUD Operations | 111,218 | 12,035 | 99,183 | 6.2 h |
| **Bad Request** | **89,002** | **89,002** | 0 | 4.8 h |
| OPNsense Filter Log | 52,379 | 0 | 52,379 | 6.4 h |
| Chat | 43,072 | 1,613 | 41,459 | 4.5 h |
| **Honeypot** | **12,090** | **12,090** | 0 | 2.0 h |
| **Exception** | **10,804** | **10,804** | 0 | 4.8 h |
| **Alert** | **8,040** | **8,040** | 0 | 2.0 h |
| OPNsense Syslog | 4,888 | 0 | 4,888 | 6.4 h |
| **Rate Limit** | **3,390** | **3,390** | 0 | 2.0 h |
| OPNsense Suricata | 2,635 | 0 | 2,635 | 6.2 h |
| Snort IDS | 2,501 | 0 | 2,501 | 5.1 h |
| Document | 2,010 | 1,981 | 29 | 2.0 h |
| OPNsense NTPd | 1,709 | 0 | 1,709 | 6.4 h |
| Fingerprint | 1,612 | 0 | 1,612 | 5.1 h |
| Authentication | 1,048 | 681 | 367 | 5.9 h |
| **Forbidden** | **995** | **995** | 0 | 5.7 h |
| IIS | 120 | 0 | 120 | 6.2 h |
| Database Backup | 90 | 5 | 85 | 2.0 h |
| OPNsense Lighttpd | 57 | 0 | 57 | 6.3 h |
| OPNsense Unbound | 33 | 0 | 33 | 2.4 h |
| Log | 31 | 1 | 30 | 3.3 h |
| OPNsense Captiveportal | 19 | 0 | 19 | 5.1 h |
| Error | 19 | 0 | 19 | 2.3 h |
| OPNsense Dnsmasq | 6 | 0 | 6 | 2.4 h |
| **Total** | **347,768** | **140,637** | **207,131** | |

Bold rows indicate fully malicious traffic classes.

## Key Data Sources

### Blazor ApplicationAudit / AuthAudit

Primary audit trail from the .NET 10 Blazor WebAssembly SPA. Each event passes through JWT + session verification middleware and a six-phase enrichment pipeline. Fields include user identity, IP, user-agent, event type, HTTP status, resource context, client certificate, fingerprint hash (HMAC-SHA256 over ~30 browser characteristics), and the `Suspicious` boolean label with categorical description.

### p0f (Passive OS Fingerprinting)

Per-session device inventory with MAC address, estimated OS, hostname, first/last seen timestamps — correlated by IP and time window with Blazor events. Enables cross-layer consistency checks (e.g., JWT claims Windows but TCP/IP stack is Linux).

### Captive Portal

Authentication-layer events from OPNsense captive portal: client IP, proxy-behind IP, fingerprint HMAC, user-agent (both PHP and JS), referrer, SHA-256 integrity hash. Provides an additional IP-to-MAC correlation source.

### Network Infrastructure

OPNsense firewall logs (filter, Suricata, syslog, NTPd, Unbound, Lighttpd, Captiveportal, Dnsmasq), Snort IDS alerts, IIS reverse proxy logs.

## Analysis Tool: `splunk_csv_analyzer.py`

A standalone Python 3 script that parses Splunk CSV exports and produces both human-readable reports and publication-ready LaTeX tables. It dynamically classifies events into traffic classes by parsing the colon-delimited sourcetype taxonomy (e.g., `security:badrequest` → "Bad Request", `application:model` → "CRUD Operations") without hardcoded if/elif chains.

**Usage:**
```bash
python3 splunk_csv_analyzer.py export_22Dec2025_010633.csv
```

**Output files:**
- `export_22Dec2025_010633_report.log` — plain-text tables (summary, per-host, per-sourcetype, traffic class, dataset composition)
- `export_22Dec2025_010633_tables.tex` — LaTeX tables ready for inclusion in academic papers (booktabs formatting, security sourcetypes highlighted in `\textcolor{darkred}`)

The output of the script execution is available at: [`export_22Dec2025_010633_report.log`](./CSV_Inventory/Golden_Sample_CSV/export_22Dec2025_010633_report.log)

**Generated tables:**
1. Summary (Host × Source × Sourcetype)
2. Per-Host event distribution
3. Per-Sourcetype event distribution
4. Traffic Class distribution (fine-grained)
5. Dataset Composition (high-level, suitable for paper Table environments)

No external dependencies beyond the Python standard library.

## How to Use

**Decompress Golden Sample CSV:**
```bash
7z x export_22Dec2025_010633.csv.7z
```

**Verify integrity:**
```bash
echo "cce55ca294323909a5ea8f99e97d581ebae74d9964999d58e0f466a21747cc1d  export_22Dec2025_010633.csv" | sha256sum -c
```

# Dataset Elaboration

## ETL Pipeline and Dataset Processing

A set of transformations was applied in order to extract the relevant fields required for the subsequent processing stages from the considerable amount of data collected. In many cases, the same event is recorded by multiple sources, resulting in redundant information. Therefore, a correlation process is used to consolidate these events into a single, unified log. The transformations applied to the data are designed to generate a list of complete individual requests by aggregation on common parameters, including IP, User, and a restricted time window. This approach makes it possible to group all events performed by a user during a single session in chronological order. The aim is to produce a simplified format that includes only the essential features required for graph construction and for supporting the computation of trustness weights. Therefore, aggregated events are separated into individual logs, containing the corresponding user, IP, and relevant information, including the classification label and the requested resource. Device-related information is linked by matching the extracted IP and timestamp with devices detected on the network at the same time through fingerprinting. If such information is unavailable, a fallback mechanism searches for the data in captive portal. This pre-processed dataset contains 281.692 records, of which 141.123 are legitimate and 140.569 are malicious.

## Request Final Dataset Composition

| Field        | Type     | Description |
|--------------|----------|-------------|
| user         | String   | Identifier of the user who generated the event. |
| ip           | String   | Associated source IP address. |
| role         | String   | User role at the time of the event; if unavailable, the default value *User* is assigned. |
| mac          | String   | MAC address of the device associated with the event. |
| hostname     | String   | Hostname of the device. |
| certificate  | String   | Client certificate used during the connection. |
| source       | String   | Source of the event. |
| event_time   | DateTime | Timestamp of the event. |
| event_type   | String   | Type of the event. |
| resource     | String   | Resource involved in the event. |
| suspicious   | Boolean  | Indicator of suspicious behavior; classification label. |
| status_code  | Integer  | HTTP status code associated with the event. |

## How to replicate the experiment

To replicate the experiments conducted on the various models, the scripts used are provided in the [`models`](./models) folder.

To use the GNN models, the [`CSV dataset`](./CSV_Inventory/Golden_Sample_CSV/export_22Dec2025_010633.csv.7z) must first be converted into JSON format using the [`csv_to_json.py`](./CSV_Inventory/csv_to_json.py) script. This allows the dataset to be properly read and utilized by the main script [`gnn_model_training.py`](./models/gnn_models_training.py) for correlation, graph construction and training.

The different models can be compared simply by replacing the class in the script with one of those available in [`model_copies`](./models/model_copies.txt).

For the other three baselines ([`MLP`](./models/mlp.py), [`CNN`](./models/cnn.py), and [`XGBoost`](./models/xg.py)), their respective scripts can be executed directly, as they rely on [`final_output_correlated.json`](./CSV_Inventory/final_output_correlated.zip) file.

An important note is that the extracted datasets must be placed in the same path as the scripts in order to be correctly read.

## Citation

If you use this dataset in your research, please cite article references.

## License

This dataset is released for academic and research purposes. See `LICENSE` for details.
