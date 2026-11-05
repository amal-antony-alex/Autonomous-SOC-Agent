# Autonomous SOC Analyst Agent (Human-Gated)

An AI-assisted Security Operations Center (SOC) investigation platform
that ingests security alerts, enriches and correlates evidence, performs
multi-model analysis, validates findings, and presents investigation
results for analyst review. The system is designed around a human-gated
response model: AI can investigate and recommend actions, but
consequential response execution remains under human control.

**Development timeline:** August 2026 -- November 2026\
**Primary integration:** Wazuh 4.14.7\
**Repository:**
[amal-antony-alex/Autonomous-SOC-Agent](https://github.com/amal-antony-alex/Autonomous-SOC-Agent)

------------------------------------------------------------------------

## Table of Contents

-   [Overview](#overview)
-   [Objectives](#objectives)
-   [Architecture](#architecture)
-   [Core Capabilities](#core-capabilities)
-   [Technology Stack](#technology-stack)
-   [Measured Results](#measured-results)
-   [Custom CyberLLM](#custom-cyberllm)
-   [Security and Human Oversight](#security-and-human-oversight)
-   [Deployment](#deployment)
-   [Project Structure](#project-structure)
-   [Current Limitations and Scope](#current-limitations-and-scope)
-   [Roadmap](#roadmap)
-   [Acknowledgements](#acknowledgements)

------------------------------------------------------------------------

## Overview

Security Operations Centers process alerts from SIEM, endpoint, network,
and threat-intelligence systems. High alert volumes, repetitive
investigations, false positives, and fragmented evidence can increase
analyst workload and delay incident triage.

The Autonomous SOC Analyst Agent addresses this problem through a
modular investigation pipeline combining deterministic security rules, a
custom cybersecurity-focused language model, retrieval-augmented
generation (RAG), independent model-assisted analysis, and evidence
validation.

The current implementation uses Wazuh as its primary verified alert
source. It processes alerts through a FastAPI backend, persists
operational data in PostgreSQL, and dispatches investigations through
Redis to a dedicated AI worker. A React-based dashboard provides the
analyst-facing interface.

The project is an AI-assisted SOC prototype, not a replacement for a
production SOC team or a fully autonomous response platform.

## Objectives

1.  **Automate alert handling:** Ingest, normalize, deduplicate,
    prioritize, and persist security alerts.
2.  **Support evidence-led investigation:** Combine rulebook matches,
    contextual retrieval, IOC analysis, alert correlation, and MITRE
    ATT&CK mapping.
3.  **Improve decision quality:** Validate findings and distinguish True
    Positive, False Positive, and Uncertain outcomes.
4.  **Preserve analyst authority:** Require human review and approval
    before consequential response actions.
5.  **Provide an extensible platform:** Separate ingestion,
    investigation, AI inference, persistence, and dashboard services.

## Architecture

### High-level workflow

``` text
Wazuh Security Alerts
        |
        v
FastAPI Alert Ingestion
        |
        v
Normalization and Deduplication
        |
        v
Rulebook Filtering and Matching
        |
        v
PostgreSQL Alert Persistence
        |
        v
Redis Investigation Queue
        |
        v
AI Investigation Worker
        |
        +-------------------------------+
        |                               |
        v                               v
Custom Tiny CyberLLM              RAG Knowledge Retrieval
        |                         (Embeddings + FAISS)
        |                               |
        +---------------+---------------+
                        |
                        v
             Qwen Cross-Verification
                        |
                        v
             Evidence and Decision
                  Validation
                        |
                        v
           Decision and Severity Output
       True Positive / False Positive / Uncertain
          Critical / High / Medium / Low
                        |
                        v
             Investigation Record
                        |
                        v
             Analyst Dashboard
                        |
                        v
              Human Review Gate
                        |
              Approval / Rejection
                        |
                        v
          Controlled Response Workflow
```

### Component responsibilities

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  Wazuh                               Primary verified source of security
                                      alerts and endpoint events

  FastAPI backend                     Alert ingestion, API endpoints,
                                      normalization, deduplication, and
                                      orchestration

  Rulebook engine                     Deterministic filtering and
                                      matching against defined SOC use
                                      cases

  Custom Tiny CyberLLM                Experimental cybersecurity-focused
                                      language-model analysis

  RAG pipeline                        Retrieves relevant cybersecurity
                                      knowledge and contextual material

  Qwen                                Secondary model used for deeper
                                      analysis and cross-verification

  Evidence and Decision Validator     Checks whether conclusions are
                                      supported by available evidence and
                                      handles uncertainty

  PostgreSQL                          Persistent storage for alerts,
                                      investigations, and incident
                                      records

  Redis                               Investigation queue and
                                      asynchronous work coordination

  React dashboard                     Analyst-facing monitoring and
                                      investigation interface

  Human approval gate                 Keeps consequential response
                                      decisions under analyst control
  -----------------------------------------------------------------------

## Core Capabilities

### Alert ingestion and processing

-   Wazuh alert integration through a custom backend integration.
-   FastAPI-based alert ingestion.
-   Alert normalization and deduplication.
-   Rulebook-based filtering and SOC use-case matching.
-   PostgreSQL persistence for accepted alerts.
-   Redis-backed asynchronous investigation processing.

### AI-assisted investigation

-   Custom Transformer-based Tiny CyberLLM developed using PyTorch.
-   Cybersecurity instruction-data preparation and fine-tuning
    workflows.
-   Retrieval-augmented investigation using embeddings and FAISS.
-   Qwen-based secondary analysis and cross-verification.
-   Investigation support for alerts, logs, indicators of compromise
    (IOCs), and incident summaries.

### Evidence-based decision support

-   Evidence and Decision Validator.
-   Three decision outcomes: True Positive, False Positive, and
    Uncertain.
-   Four severity levels: Critical, High, Medium, and Low.
-   Uncertainty handling and human-review requirements.
-   Safeguards intended to prevent failed or uncertain investigations
    from triggering response actions.

### Analyst workflow

-   Investigation and incident persistence.
-   Dashboard-based alert and investigation visibility.
-   Pending-review workflow.
-   Human approval/rejection boundary for consequential response
    actions.
-   Docker-based service deployment foundation.

## Technology Stack

  -----------------------------------------------------------------------
  Layer                               Technologies
  ----------------------------------- -----------------------------------
  SIEM / Alert Source                 Wazuh 4.14.7

  Backend                             Python 3.12.11, FastAPI

  Custom LLM                          PyTorch, Transformer architecture,
                                      Byte Pair Encoding (BPE) tokenizer

  Secondary Model                     Qwen 0.6B through a local inference
                                      runtime

  Retrieval                           Sentence Transformers, embeddings,
                                      FAISS

  Database                            PostgreSQL 16

  Queue / Cache                       Redis 7

  Frontend                            React, Vite, Tailwind CSS

  Containers                          Docker, Docker Compose

  Testing                             Pytest
  -----------------------------------------------------------------------

## Measured Results

The following figures are taken from recorded development runs. They
describe specific test environments and workloads; they should not be
interpreted as production service-level guarantees.

### 1. Alert ingestion benchmark

A controlled 100-alert ingestion run produced the following recorded
results:

  Metric                                         Result
  ----------------------------- -----------------------
  Alerts submitted                                  100
  Alerts accepted / persisted                       100
  Duplicate alerts reported                           0
  Ingestion failures reported                         0
  Total ingestion time                    0.969 seconds
  Throughput                      103.235 alerts/second
  Mean ingestion latency                         9.5 ms
  P95 ingestion latency                         14.3 ms

**Interpretation:** The tested ingestion path accepted and persisted all
100 submitted alerts in the recorded run. This is a benchmark of the
ingestion path, not a measurement of end-to-end AI investigation
throughput.

### 2. Investigation processing

The recorded 100-alert investigation run produced:

  Metric                                     Result
  --------------------------------- ---------------
  Investigations created                        100
  Completed investigations                       98
  Failed investigations                           2
  Completion rate                               98%
  Failure rate                                   2%
  Mean investigation time             24.18 seconds
  Median investigation time (P50)     12.97 seconds
  P95 investigation time              61.66 seconds

The investigation window recorded in the run was approximately 40
minutes and 26 seconds, equivalent to an average of approximately 2.47
investigations per minute across that window. This wall-clock rate
includes the effects of the asynchronous worker and model-inference
runtime and is distinct from alert-ingestion throughput.

**Observed model-runtime behavior:** Typical recorded component timings
were approximately 0.13--0.23 seconds for Tiny CyberLLM inference,
0.02--0.08 seconds for RAG retrieval, and 12--16 seconds for Qwen
inference. Outlier delays were also observed, including longer RAG and
Qwen calls. These observations indicate that secondary model inference
and occasional retrieval outliers can dominate investigation duration.

### 3. Investigation and review state

A recorded dashboard/database verification after the 100-alert run
showed:

  Metric                        Recorded state
  --------------------------- ----------------
  Alerts                                   101
  Investigations                           102
  Pending reviews                          100
  Incidents                                  0
  Executed response actions                  0

The counts above reflect the application state at that verification
point, including records outside the isolated 100-alert benchmark. In
the 100-alert investigation run, 98 investigations were recorded as
completed and 2 as failed. The completed results in that run were marked
Uncertain and required human review; no automated response action was
executed.

### 4. Automated test results

  Test milestone                                            Result
  ------------------------------- --------------------------------
  Earlier focused unit-test run                          22 passed
  Later broader unit-test run                           115 passed
  Dashboard HTTP health check                             HTTP 200
  FastAPI service health check                            HTTP 200
  Redis connectivity check                                    PONG
  Investigation worker              Queue-processing loop verified
  Backend container                           Started and verified
  Frontend image                                  Built / verified

The 22-test and 115-test results belong to separate test milestones. The
later recorded suite completed with 115 passing tests and 2 warnings.

### 5. Custom CyberLLM evaluation

The custom model was evaluated using a fixed held-out test split. The
recorded dataset contained 3,837 examples:

  Dataset split      Examples
  --------------- -----------
  Training              3,054
  Validation              392
  Test                    391
  **Total**         **3,837**

The base and fine-tuned checkpoints were evaluated on the same
391-example test set.

  Metric                 Base model   Fine-tuned model
  -------------------- ------------ ------------------
  Held-out test loss       6.734678           4.164781

**Relative test-loss reduction: 38.16%.**

The training run also recorded:

  Metric                                                   Value
  ---------------------------------------- ---------------------
  Initial training loss                                 5.607630
  Final recorded training loss                          4.315819
  Validation loss before fine-tuning                    6.829106
  Validation loss after fine-tuning                     4.227356
  Validation-loss reduction                  Approximately 38.1%
  Fine-tuning epochs in the recorded run                       3
  Maximum sequence length                                    512
  Evaluation examples                                        391

All eight evaluated task categories showed lower test loss after
fine-tuning:

-   Alert analysis
-   Alert correlation
-   False-positive assessment
-   Incident summary
-   IOC analysis
-   MITRE ATT&CK mapping
-   Severity classification
-   Uncertainty analysis

**Important evaluation note:** Lower language-model loss indicates
improved next-token prediction on the held-out dataset. It does not, by
itself, establish factual correctness, reliable threat detection, low
hallucination rates, or production-grade SOC reasoning. Qualitative
evaluation and operational safeguards remain necessary.

## Custom CyberLLM

A small Transformer language model was implemented in PyTorch rather
than relying exclusively on a hosted language-model API.

The recorded model configuration includes:

  Parameter                              Configuration
  ----------------------------- ----------------------
  Embedding dimension                              128
  Transformer layers                                 2
  Attention heads                                    4
  Feed-forward dimension                           512
  Vocabulary size                                2,000
  Approximate parameter count                  976,000
  Maximum context length                    512 tokens
  Tokenization                    Custom BPE tokenizer

The development workflow includes pretraining, cybersecurity
instruction-data preparation, supervised fine-tuning, checkpoint
management, training diagnostics, and held-out evaluation.

The model remains an experimental component. Its measured loss
improvement is a useful training result, but generated SOC conclusions
must continue to be checked against evidence and independently reviewed.

## Security and Human Oversight

The system is intentionally designed to avoid treating model output as
an authoritative security decision.

-   AI findings are subject to evidence validation.
-   The decision layer supports True Positive, False Positive, and
    Uncertain outcomes.
-   Uncertain findings are routed for human review.
-   Failed investigation records must not be treated as successful
    incident determinations.
-   Consequential response actions require explicit human authorization.
-   The project does not claim unrestricted autonomous containment,
    remediation, or production endpoint response.

These controls are central to the project's human-gated design.

## Deployment

The application is organized as containerized services. The recorded
development environment includes the backend, AI worker, PostgreSQL,
Redis, and frontend components. Wazuh is maintained as the primary
security-alert source and is operated as a separate stack.

### Prerequisites

-   Docker Engine
-   Docker Compose
-   Git

### Clone the repository

``` bash
git clone https://github.com/amal-antony-alex/Autonomous-SOC-Agent.git
cd Autonomous-SOC-Agent
```

### Configure environment variables

Create a local environment file from the supplied example:

``` bash
cp .env.example .env
```

Review `.env` and set the required database, Redis, model-runtime, and
service configuration values for your environment. Do not commit secrets
or production credentials.

### Start the application

``` bash
docker compose up --build
```

To run services in the background:

``` bash
docker compose up --build -d
```

### Inspect service status and logs

``` bash
docker compose ps
docker compose logs -f
```

The exact service names, exposed ports, and environment variables are
defined by the Compose and environment files in the repository. Wazuh
setup and connectivity must be configured separately.

## Project Structure

The repository is organized by responsibility. The following is a
high-level guide; consult the current repository tree for the exact
files and modules.

``` text
Autonomous-SOC-Agent/
├── ai/
│   └── tiny_llm/
│       ├── model/
│       ├── tokenizer/
│       ├── training/
│       ├── checkpoints/
│       └── evaluations/
├── backend/
│   └── app/
│       ├── api/
│       ├── models/
│       ├── schemas/
│       ├── services/
│       ├── integrations/
│       └── ...
├── frontend/
├── data/
├── docs/
├── tests/
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

## Current Limitations and Scope

The project is under active development. The following boundaries are
important when interpreting the results:

-   Wazuh is the primary verified alert-source integration. Other SIEM,
    EDR/XDR, IDS/IPS, firewall, and threat-intelligence integrations
    should be treated as planned or integration-ready unless
    independently demonstrated in the current repository.
-   The 100-alert benchmark validates a specific ingestion and
    investigation run. It does not demonstrate sustained 1,000- or
    5,000-alert end-to-end processing.
-   The architecture has a 1,000+ alert handling objective, but this
    remains a scalability target rather than a verified throughput
    claim.
-   The custom CyberLLM has demonstrated a reduction in held-out
    language-model loss, but its SOC reasoning quality is not yet
    established as production reliable.
-   Qwen inference and retrieval showed variable latency, including
    outliers.
-   The recorded 100-alert investigation run included 2 failures and 98
    Uncertain outcomes requiring human review.
-   Precision, recall, F1-score, false-positive reduction rate,
    false-negative rate, MTTD, MTTR, and production resource-utilization
    figures are not claimed here because a completed, reproducible
    benchmark for those metrics has not been established in the recorded
    results.
-   Automated response execution is not represented as production-ready.
    Human approval remains mandatory for consequential actions.

## Roadmap

-   [x] Establish project architecture and development environment.
-   [x] Deploy Wazuh and generate a real SSH security alert.
-   [x] Integrate Wazuh alert delivery with the FastAPI backend.
-   [x] Implement alert normalization, deduplication, rulebook matching,
    and PostgreSQL persistence.
-   [x] Build the custom Tiny Transformer and BPE tokenizer.
-   [x] Prepare cybersecurity instruction data and fine-tuning
    workflows.
-   [x] Implement the RAG foundation using embeddings and FAISS.
-   [x] Integrate Redis-backed investigation processing and an AI
    worker.
-   [x] Implement evidence and decision validation foundations.
-   [x] Establish True Positive / False Positive / Uncertain and
    four-level severity outputs.
-   [x] Run held-out CyberLLM evaluation and record benchmark results.
-   [x] Verify container/service health and automated test milestones.
-   [ ] Improve and qualitatively validate CyberLLM response
    reliability.
-   [ ] Expand reproducible end-to-end evaluation across alert types and
    failure conditions.
-   [ ] Complete controlled scalability benchmarks at 500, 1,000, and
    5,000 alerts.
-   [ ] Further validate analyst approval/rejection, auditability, and
    response safeguards.
-   [ ] Finalize deployment documentation and release validation.

## Acknowledgements

Built as a final-year cybersecurity project focused on practical SOC
automation, applied machine learning, evidence-based investigation, and
human oversight.

The project uses open-source security and software technologies,
including Wazuh, PyTorch, FastAPI, FAISS, PostgreSQL, Redis, React, and
Docker.
