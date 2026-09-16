\# Autonomous SOC Analyst Agent

\## Technology Stack



This document defines the finalized technology stack for the Autonomous SOC Analyst Agent.



\---



\## 1. Security Operations / Alert Sources



\### Primary SOC Platform

\- Wazuh



\### Security Data Sources

\- Wazuh security alerts

\- Simulated SIEM logs

\- Simulated EDR/XDR alerts

\- Simulated IDS/IPS alerts

\- Firewall logs

\- Threat intelligence data



Wazuh will be the primary implemented security source. Other sources will initially be simulated or integration-ready.



\---



\## 2. Rulebook / SOC Use Cases



The Rulebook will contain detection and investigation logic for:



\- Brute Force

\- Malware Detection

\- Suspicious PowerShell

\- Privilege Escalation

\- Impossible Login

\- Port Scanning

\- Suspicious Network Activity

\- Lateral Movement

\- Data Exfiltration

\- Active Directory



\---



\## 3. AI / Machine Learning



\### Framework

\- Python

\- PyTorch



\### Tiny LLM

\- Custom Transformer architecture

\- Built from scratch using PyTorch



\### CyberLLM

\- Tiny LLM fine-tuned for cybersecurity and SOC analysis

\- PyTorch-based training



\### Deep Analysis Model

\- Qwen

\- Local deployment



Qwen will be used for deeper investigation and cross-verification when required.



\---



\## 4. RAG



\### Vector Database

\- FAISS



\### Components

\- Embedding model

\- FAISS vector index

\- Retriever

\- Context builder



RAG will provide relevant cybersecurity knowledge and supporting evidence to the AI models.



\---



\## 5. Backend



\### API Framework

\- FastAPI



\### Language

\- Python



\### Port

\- 8000



The backend will coordinate alert ingestion, analysis, RAG, AI inference, risk assessment, investigation, response recommendations, and human-gated actions.



\---



\## 6. Database



\### Database

\- PostgreSQL



\### Port

\- 5432



PostgreSQL will store:



\- Alerts

\- Incidents

\- IOCs

\- Evidence

\- Severity

\- Confidence

\- TP/FP/Uncertain decisions

\- Investigation results

\- Analyst feedback

\- Response history



\---



\## 7. Queue and Alert Processing



\### Queue / Optimization

\- Redis



\### Port

\- 6379



Redis will support:



\- Asynchronous processing

\- Alert queues

\- Priority processing

\- High-volume alert handling

\- Temporary task/state management



The system will use:



\- Deduplication

\- Alert clustering

\- Priority queues

\- Batch processing

\- Selective Qwen usage



to support processing of 1000+ alerts.



\---



\## 8. Frontend



\### Framework

\- React



\### Styling

\- Tailwind CSS



\### Web Server

\- Nginx



\### Host Port

\- 3000



The dashboard will provide visibility into alerts, investigations, severity, evidence, incidents, recommendations, human approval, and response history.



\---



\## 9. Response Engine



\### Technologies

\- Python

\- FastAPI

\- Wazuh API

\- Security tool APIs



The Response Engine will execute only human-approved actions.



Initially, response actions will use sandboxed or simulated actions rather than destructive real-world actions.



\---



\## 10. Containerization and Deployment



\### Containerization

\- Docker



\### Orchestration

\- Docker Compose



The development environment will contain services for:



\- FastAPI Backend

\- React Dashboard

\- Wazuh

\- PostgreSQL

\- Redis

\- FAISS / RAG

\- Tiny CyberLLM

\- Qwen

\- Prometheus

\- Grafana



\---



\## 11. Monitoring



\### Metrics

\- Prometheus

\- Port 9090



\### Visualization

\- Grafana

\- Host Port 3001

\- Container Port 3000



Monitoring will be used to observe system health, processing performance, and service metrics.



\---



\## 12. Development and Version Control



\- Git

\- GitHub

\- Python virtual environment

\- VS Code



\---



\## 13. Overall Architecture



Security Sources

↓

Alert Ingestion

↓

Rulebook / SOC Use Cases

↓

Initial Alert Filtering

↓

Tiny CyberLLM

↓

Alert / IOC / Log Analysis

↓

Alert Correlation

↓

Threat Enrichment

↓

RAG

↓

Qwen

↓

Risk Assessment

↓

Severity Classification

↓

Evidence \& Decision Validator

↓

False Positive / True Positive / Uncertain

↓

Investigation

↓

Response Recommendations

↓

Human Gate

↓

Response Engine

↓

Incident Report

↓

Analyst Feedback

↓

Continuous Improvement



\---



\## Status



Technology stack finalized for development.

