# Prior art and provenance

This repository contains a CodeQL query pack that detects, in Go-based Kubernetes
operators, secret material from Kubernetes `Secret` objects flowing into custom-resource
fields, and custom-resource fields flowing into SQL sinks. It also models how operators
register their custom resource types.

This note records when the work was done, because a later independent publication covers
overlapping ground.

## Timeline (from this repository's git history)

All dates are commit **author dates**, which git records at the time the work was written.

| Date | Commit | What existed |
|---|---|---|
| 2022-10-03 | `f720f6b` | First commit — exploratory CodeQL queries over Kubernetes operators |
| 2022-10-06 | `49d6153` | First draft of taint tracking |
| 2022-10-09 | `153ab51` | Modeling reads of `secret.Data[_]` as a taint source |
| 2022-11-07 | `3376016` | Taint-tracking test scaffolding |
| 2023-04-30 | `dcf0d4d` | "all works" — the secret-to-custom-resource taint query working end to end |
| 2023-05-01 | `9564c95` | "working queries" — including custom-resource-type detection via scheme registration |
| 2023-09-19 | `9a2acc7` | Pack packaging |
| 2024-10-25 | `2e6dfba` | Tuning |
| 2026-08-30 → | `def625b` … | Modernisation: dataflow-API migration, shared library, tests, CI, false-positive tuning, client-go and table-driven registration idioms |

The core idea — CodeQL interprocedural taint tracking from Kubernetes `Secret` data into
custom-resource fields in Go operators, with custom-resource types identified by their
scheme registration — was implemented and working in this repository by **April–May 2023**.

## Relationship to Chen et al., NDSS 2026

Chen, Guo, Jin, Li and Chen, *"Breaking the Bulkhead: Demystifying Cross-Namespace
Reference Vulnerabilities in Kubernetes Operators"* (NDSS 2026; arXiv:2507.03387, first
version July 2025) independently developed a CodeQL taint-tracking suite for Go Kubernetes
operators. Their work and this repository converge on notable specifics, including
identifying custom resource types by the `TypeMeta` / `ObjectMeta` embedding that Kubernetes
API types carry.

This is stated as a matter of record, not as a dispute:

- **Priority of implementation.** The taint-tracking approach here predates that paper's
  first public version by roughly two and a quarter years, as the commit author dates above
  show. This was independent work, arrived at without knowledge of the paper (which did not
  yet exist).
- **Priority of public disclosure.** This repository was private until it was made public;
  the paper was published first. Independent invention followed by later independent
  publication is common, and the two facts sit side by side without contradiction.

## What differs

The two efforts are not the same query set:

- **This pack additionally finds SQL injection** built from custom-resource fields
  (`K8sCustomResourceSqlInjection`), a class the paper does not target.
- **This pack follows secret *values*** into custom-resource fields, status, ConfigMaps and
  container environment variables, rather than only modeling cross-namespace *references*.
- **The paper additionally models cluster-scoped resource references** — for example an
  operator creating a `ClusterRoleBinding` for a service account in the caller's namespace,
  escalating a namespace tenant to cluster-wide privileges — which this pack does not
  currently detect.

Neither is a superset of the other.
