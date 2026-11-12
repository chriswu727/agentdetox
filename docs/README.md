# Documentation

AgentDetox **0.6.0** was released on 2026-11-12. English is the primary language for the README,
user guide, policies, release notes and developer documentation. The
[Simplified Chinese README](../README.zh-CN.md) covers installation, the review workflow and key
limits; detailed references are maintained in English.

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
| [Large-memory protocol](../bench/LARGE_MEMORY.md) | Synthetic inventory baseline, the end-to-end library harness, and scale, cleanup and observation gates |
| [Memory benchmark v0](../bench/MEMORY_BENCHMARK.md) | Historical public-data detector comparison and synthetic transcript evaluation |
| [Knowledge-base benchmark](../bench/KB_BENCHMARK.md) | Historical scanner comparison on public RAG data |
| [Real-agent lab](../lab/README.md) | Protocol, authorization, costs, outcome definitions and dated runs; the [0.6.0 candidate run](../lab/README.md#060-candidate-2026-11-11) passed 9 of 12 scenarios with AgentDetox only |
| [Cross-client disinfection](client-validation.md) | 2026-11-10 file workflows, native-client checks, latency and known gaps |
| [Last run of both lab arms](../lab/results/latest.md) | 0.5.0 candidate, 12 Claude Code scenarios with and without AgentDetox. 23 of 24 checks passed. |

## Develop and contribute

- [Contributing](../CONTRIBUTING.md): setup, required checks, documentation language and releases.
- [Architecture](architecture.md): hook processing, observation, storage, recovery and library inspection.
- [Design decisions](decisions.md): choices and their trade-offs.

Attack payloads in `lab/fixtures`, `examples` and benchmark data are test material. Their language
and instructions are deliberate fixtures, not documentation guidance.
