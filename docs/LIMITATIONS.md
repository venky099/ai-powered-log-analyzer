# Limitations and Operational Boundaries

## Scope & Purpose

The **AI-Powered Log Analyzer** is developed as a defensive, educational triage workbench and portfolio demonstration project. It is **not** an enterprise Security Information and Event Management (SIEM) solution, nor is it an automated intrusion prevention system (IPS).

---

## Technical & Analytical Limitations

### 1. Log Format Diversity
- Systems and custom applications log events in thousands of disparate formats (JSON, RFC 5424 syslog, Apache Common/Combined, Windows Event Log XML/EVTX, CSV, custom unstructured text).
- While the parser handles standard timestamp conventions and normalized severity keywords, unstandardized logs may have their timestamps or severities unrecognized and will be parsed as general text lines.

### 2. False Positives & False Negatives
- **Repeated Authentication Failures:** Flagging multiple failed logins from an IP address indicates an investigation lead, **not** definitive proof of malicious attack or brute-force behavior. Common benign causes include:
  - Misconfigured automated build agents or API clients with expired credentials.
  - Users behind enterprise NAT gateways or corporate proxies sharing a single external IP.
  - Legitimate users forgetting their passwords.
- **Keywords in Unrelated Messages:** Words like `error`, `failed`, or `panic` occurring in debug traces, URLs, or query parameters can trigger heuristic rules unless verified against contextual logs.

### 3. Missing Context & Telemetry
- A single log file offers limited visibility into complete incident lifecycles.
- An analyst cannot determine whether an authentication attempt succeeded without comparing with subsequent authentication logs across all ingress endpoints.
- Source IP spoofing (over UDP) or proxy headers (`X-Forwarded-For`) can be falsified unless validated against perimeter load balancers.

### 4. Local AI Model Constraints
- Local small-scale LLMs (such as `llama3.2:1b`) have finite reasoning capacity and may occasionally generalize or misinterpret complex log sequences.
- The local AI module is strictly advisory:
  - It does **not** alter rule detections.
  - It receives pre-filtered, structured findings rather than unconstrained raw file data.
  - All AI output should be cross-referenced with the raw log evidence provided in the dashboard.

### 5. Scale & Ingestion Limits
- Default web file upload limits are bounded (2 MB by default) to preserve in-memory processing responsiveness on standard workstations.
- Large production log streams (hundreds of gigabytes per hour) require distributed streaming pipelines (e.g., Elasticsearch, OpenSearch, Kafka, ClickHouse).

---

## Defensive Best Practices

1. **Always Verify Raw Evidence:** Never take an AI or automated alert at face value without clicking into the raw evidence lines.
2. **Correlate with Network Telemetry:** Check firewall, DNS, and NetFlow records before initiating IP blocks.
3. **Protect Sensitive Logs:** Application logs may contain PII, session tokens, or internal network IPs. Always adhere to your organization's data handling policies.
