# Documentation

AgentDetox **0.4.1** was released on 2026-11-05. English is the primary language for the README,
user guide, policies, release notes and developer documentation. The
[Simplified Chinese README](../README.zh-CN.md) covers installation, the review workflow and key
limits; detailed references are maintained in English. Keep both READMEs aligned when behavior changes.

## Use AgentDetox

| Start here | Contents |
|---|---|
| [Project home](../README.md) | Overview, quick start, current support and evidence |
| [User guide](user-guide.md) | Installation, behavior, review commands, settings, upgrades, recovery and removal |
| [Coverage and limits](user-guide.md#what-it-does-not-catch) | Shell boundaries, background writes, attribution and recovery limits |
| [Agent integrations](user-guide.md#other-agents) | Supported Claude Code integration and experimental alternatives |
| [Privacy](../PRIVACY.md) | Local data, sensitive file copies, downloads, retention and deletion |
| [Security](../SECURITY.md) | Threat model and private vulnerability reporting |
| [Changelog](../CHANGELOG.md) | Released changes and unreleased work |
| [Roadmap](../ROADMAP.md) | Implemented work and future directions |

## Inspect the evidence

These reports measure different things. None is an overall detection-accuracy score.
Dated measurements retain their original fixtures, methods and results; historical reports are
not silently refreshed to describe current code.

| Report | Scope |
|---|---|
| [Offline regression gallery](../bench/ACCURACY.md) | Prevention, monitoring, recovery and explicit known misses; no model calls |
| [Hook latency](../bench/HOOK_LATENCY.md) | Dated measurements, raw reports and per-case budgets |
| [Large-memory protocol](../bench/LARGE_MEMORY.md) | Synthetic inventory baseline and future scale, cleanup and observation gates |
| [Memory benchmark v0](../bench/MEMORY_BENCHMARK.md) | Historical public-data detector comparison and synthetic transcript evaluation |
| [Knowledge-base benchmark](../bench/KB_BENCHMARK.md) | Historical scanner comparison on public RAG data |
| [Real-agent lab](../lab/README.md) | Protocol, authorization, costs and outcome definitions |
| [Latest recorded lab run](../lab/results/latest.md) | 2026-11-02, 16 real Claude Code sessions; not a new run for this documentation update |

## Develop and contribute

- [Contributing](../CONTRIBUTING.md): setup, required checks, documentation language and releases.
- [Architecture](architecture.md): hook processing, observation, storage and recovery.
- [Design decisions](decisions.md): choices and their trade-offs.

Attack payloads in `lab/fixtures`, `examples` and benchmark data are test material. Their language
and instructions are deliberate fixtures, not documentation guidance.
