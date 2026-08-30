# Exploration queries

These are AST-exploration aids, not alerts. They were used to inspect how a Kubernetes
operator registers its custom resources, where it reads `Secret` data, and which struct
writes look like sinks — the raw material from which the two security queries under
`../Security/` were derived. They deliberately carry no query metadata (no `@kind`,
`@id`, or `@tags`), so the `codeql-suites/k8s-operators.qls` suite filter excludes them
from any security run; use them only by running a file directly against a database.
