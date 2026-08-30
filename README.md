# codeql-k8s-operator-secrets

A CodeQL query pack (`hoeg/k8s-operators`) for Kubernetes operators written in Go.

It looks for two things:

1. **Secret values ending up in custom resources.** A value read out of the `Data` or
   `StringData` map of a `k8s.io/api/core/v1.Secret` that flows, through taint, into a
   string field of a type the operator registered as a custom resource. A `Secret` has its
   own storage, its own RBAC and can be encrypted at rest; a custom resource has none of
   that, so copying the plaintext into a CR spec or status widens who can read it —
   including anyone reading `kubectl get -o yaml`, a GitOps mirror, or an audit log entry.
2. **Custom resource fields reaching SQL sinks.** A string field of a registered custom
   resource that flows into a SQL or NoSQL query sink. Whoever can create or edit that
   custom resource controls the field's contents, so if the operator concatenates it into
   query text they control part of the query.

Both queries are `@kind path-problem`, so each result carries the flow path from source to
sink.

**Status: useful, unproven.** The pack was developed against a single operator,
[`github.com/humio/humio-operator`](https://github.com/humio/humio-operator), and has not
been validated against any other. There is a synthetic query-test suite under `test/` that
pins the source, sink and field-traversal behaviour, and CI runs it on every push, but a
passing test suite is not a false-positive or false-negative measurement on real code. Both
queries are `@precision medium` on purpose. Read the [Limitations](#limitations) section
before you treat an empty result as an all-clear or a reported path as a finding.

## Install

All install commands below were executed on macOS arm64 and exited 0.

```sh
# 1. CLI (cask, not formula). Symlinks /opt/homebrew/bin/codeql -> Caskroom/codeql/2.26.4/codeql/codeql
brew install --cask codeql
codeql version --format=terse            # -> 2.26.4
codeql resolve languages | grep '^go'    # -> go: .../codeql/go   (extractor ships in the cask)

# 2. Query libraries (NOT in the cask; they come from the package registry)
cd codeql-k8s-operator-secrets/src
codeql pack install                      # -> codeql/go-all 7.3.0 + 9 transitive deps into ~/.codeql/packages
                                         #    writes codeql-pack.lock.yml — it is committed, keep it so

# 3. VS Code extension (optional)
code --install-extension GitHub.vscode-codeql   # -> 1.17.8
```

No `PATH` change is needed if `/opt/homebrew/bin` is already on it. The
`codeql-bundle-osx64` download is **not** required — the Go extractor
(`codeql/go/tools/osx64/go-extractor`, `go.dbscheme`) is inside the cask; only the QL
libraries were missing, and `codeql pack install` supplies them. Upgrade with
`brew upgrade --cask codeql`.

## Compile, format and test

These are the gates for every change. All four are run from the repository root, and
`.github/workflows/ci.yml` runs the same four (plus a pack-resolution check) on every push
and pull request:

```sh
cd codeql-k8s-operator-secrets
codeql pack install --mode verify src/                                   # lock file is current
codeql query format --check-only $(find src -name '*.ql' -o -name '*.qll')
codeql query compile --check-only --threads=0 -- src/                    # whole pack
codeql test run --threads=0 -- test/                                     # query tests
```

While iterating, compile a single file instead of the whole pack:

```sh
codeql query compile --check-only -- src/Security/CWE-200/K8sSecretsLeak.ql
```

If the format gate fails, `codeql query format --in-place <file>` rewrites the offending
`.ql` or `.qll` in place; run it on anything you write before pushing.

`test/` is a separate CodeQL pack (`hoeg/k8s-operators-tests`) that depends on
`hoeg/k8s-operators` as `${workspace}`, which is why `codeql test run` must be invoked from
the repository root, where `codeql-workspace.yml` lives. Each test directory holds a Go
fixture, a `.qlref` naming the query under test, and a `.expected` file; a fixture that does
not change `.expected` proves nothing, so keep the GOOD cases in the fixtures and keep them
out of `.expected`.

## Run against an operator

```sh
git clone https://github.com/humio/humio-operator ~/src/humio-operator
cd ~/src/humio-operator && go mod download all && go build ./...   # go1.23.5 was used here
codeql database create ~/dbs/humio-db \
  --language=go --source-root=$HOME/src/humio-operator --overwrite

cd codeql-k8s-operator-secrets
codeql database analyze ~/dbs/humio-db hoeg/k8s-operators \
  --search-path=. \
  --format=sarif-latest --output=results.sarif --ram=8192 --threads=0
```

**`--search-path=.` is not optional.** A bare pack name is resolved against the package cache
(`~/.codeql/packages`) and the search path; `codeql-workspace.yml` is *not* consulted
implicitly, and this pack is neither installed into the cache nor published to a registry.
Without the flag, from this repository root:

```
$ codeql resolve queries hoeg/k8s-operators
A fatal error occurred: Query pack hoeg/k8s-operators cannot be found. Check the spelling of the pack.
$ codeql resolve qlpacks | grep -c hoeg
0
```

With the flag the name resolves to exactly the two alert queries. This is the cheap check to
run — it needs no database — if analysis picks up the wrong query set or none at all:

```sh
cd codeql-k8s-operator-secrets
codeql resolve queries --search-path=. -- hoeg/k8s-operators
# -> <repo>/src/Security/CWE-200/K8sSecretsLeak.ql
#    <repo>/src/Security/CWE-089/K8sCustomResourceSqlInjection.ql
# (two lines, absolute paths; the "Recording pack reference ..." line goes to stderr)
```

If you would rather not carry the flag, point at the suite by path instead — it prints the
same two files and resolves without it:

```sh
codeql resolve queries -- src/codeql-suites/k8s-operators.qls
```

Three notes on the `database create` / `database analyze` block:

- **The analysis itself has not been run.** No database has been built from this checkout,
  so build-mode quirks in `humio-operator` are unknown and the `database create` line may
  need adjusting for your Go toolchain. The pack *resolution* shown above was run from this
  repository root and exits 0; the `database analyze` line inherits that resolution but has
  not itself been executed.
- `--ram=8192` is explicit because `codeql resolve ram` reports only `-J-Xmx2523M` on this
  machine.
- Analyze by **pack name** (`hoeg/k8s-operators`), not by path: passing `src/` hands the
  analyzer the metadata-less exploration queries and aborts with `NO_KIND_SPECIFIED`. The
  pack's `defaultSuiteFile` (`src/codeql-suites/k8s-operators.qls`) filters on
  `kind: [problem, path-problem]` plus `tags contain: security`, which is what keeps them
  out.

## Queries

Two alert queries, under `src/Security/`. These carry full metadata and are the only ones
the default suite runs.

| Query | `@id` | Kind | Severity | Precision | Finds |
|---|---|---|---|---|---|
| `Security/CWE-200/K8sSecretsLeak.ql` | `go/k8s-secrets-leak` | path-problem | error, 10.0 | medium | `secret.Data[...]` flowing into a string field of a registered custom resource |
| `Security/CWE-089/K8sCustomResourceSqlInjection.ql` | `go/k8s-cr-sql-injection` | path-problem | error, 8.8 | medium | a custom resource string field flowing into a SQL/NoSQL sink |

Seven exploration queries, under `src/Exploration/`. They are AST-poking aids used to
derive the two above — they have **no** metadata (no `@kind`, `@id` or `@tags`), are
excluded from the suite, and are meant to be run one file at a time against a database
while working out how a particular operator is wired.

| Query | Selects |
|---|---|
| `Exploration/FindCrRegistrations.ql` | every scheme-registration call site and the type it registers (the only exerciser of `APISchemaBuilder`) |
| `Exploration/ReadSecret.ql` | arguments to `client.Get` that are `*corev1.Secret` |
| `Exploration/SecretRef.ql` | struct types embedding a `*SecretKeySelector` |
| `Exploration/SourceGetSecret.ql` | the data-flow node for the `*corev1.Secret` passed to `client.Get` |
| `Exploration/SourceGetCr.ql` | `Get` calls fetching a custom resource that transitively contains a `SecretKeySelector` |
| `Exploration/SinkWriteToCr.ql` | assignments whose LHS selects a field of such a custom resource |
| `Exploration/WriteToStruct.ql` | writes to fields of the struct types declared for registered custom resources |

Shared classes and predicates live in `src/K8sOperators.qll` at the pack root, so every
query imports them with `import K8sOperators`.

## Tests and CI

`test/` is a second pack, `hoeg/k8s-operators-tests`, wired to `src/` through
`codeql-workspace.yml`. Each subdirectory is one query test: a small self-contained Go
operator with the `k8s.io` and `sigs.k8s.io` types it needs vendored, so the extractor does
not have to fetch modules, a `.qlref` selecting the query, and a `.expected` file. The fixtures carry both
BAD cases, which must appear in `.expected`, and GOOD cases — a write to a `Deployment`'s
promoted `ObjectMeta.Name`, a write through an unregistered struct that shares its `Field`
entities with the CR spec — which must not. Run them with
`codeql test run --threads=0 -- test/` from the repository root.

`.github/workflows/ci.yml` runs, on every push and pull request: `codeql pack install --mode
verify src/`, `codeql query format --check-only`, `codeql query compile --check-only` over
`src/`, and `codeql test run` over `test/`. It also checks that `hoeg/k8s-operators` still
resolves the way this README documents.

## Limitations

Read these as constraints on what a result — or the absence of one — means.

- **Only CRs registered via `scheme.Builder.Register` are recognised.** `CustomResourceType`
  matches the base type of a pointer passed to
  `sigs.k8s.io/controller-runtime/pkg/scheme.Register`. The lower-level
  `runtime.Scheme.AddKnownTypes` branch (`APISchemaBuilder` in the library) is deliberately
  **disabled** for this purpose: `k8s.io/api/core/v1/register.go` registers the core API
  types through `AddKnownTypes`, so enabling it would make `corev1.Secret` itself a
  `CustomResourceType` whenever dependency source is extracted, and the secrets query would
  report secrets flowing into secrets. An operator that registers its types only through
  `AddKnownTypes` is invisible to both queries and will produce zero results.
- **Both `secret.Data["k"]` and `for k, v := range secret.Data` are sources.**
  `K8sSecretData` uses `DataFlow::readsAnElement`, the library's union of the index-element
  read and the range-element read, and is a `DataFlow::Node` rather than a `DataFlow::ReadNode`
  precisely so the range form survives (`RangeElementNode` is deliberately not a `ReadNode`).
  Indexing, ranging, and access through a local alias of the secret are all matched; both
  `Data` and `StringData` are covered. The range *key* is excluded on purpose — Secret keys
  are filename-like names, not secret material. `test/K8sSecretsLeak/test.go` pins the range
  cases over both `Data` and `StringData`.
- **Writing into a map or slice *element* of a CR field is not a sink.** `CustomResourceSink`
  is defined through `Write.writesField`, so `cr.Spec.Fields[key] = string(val)` is not
  reported, with or without a range loop. Only writes to the field itself are sinks. This is
  a known gap, not a deliberate exclusion.
- **Field identity in Go is structural, so a path cannot pin down *which* CR type it is in.**
  The CodeQL Go library gives structurally identical structs a single `Field` entity: given
  `type T1 struct { x int }` and `type T2 struct { x int }`, `T1.x` and `T2.x` are the same
  entity (see the `Field` class in `codeql/go-all`, `semmle/go/Scopes.qll`). Constraining the
  access base in `isCustomResourceFieldAccess` is what keeps a write through an *unregistered*
  look-alike struct out of the results — `test/K8sSecretsLeak/test.go` pins that with a
  `NotACR` type structurally identical to the CR spec — but where two *registered* CR types
  share a layout, nothing in a reported path distinguishes them. The earlier `humio-operator`
  survey found 17 status structs sharing a single `State` field. Read the path, not the field
  name.
- **Custom-resource membership is decided on types, not values.** `isPartOfCustomResource` is
  type-level reachability from a `CustomResourceType` through fields and containers. A value
  whose type is reachable from a CR counts as part of a CR even when that particular value
  never belongs to one — a standalone `MyCRSpec` local, say. The reachable-type set is also
  transitive, so a widely shared helper struct embedded in a CR pulls all of its fields in.
- **`@precision medium` is a claim about the design, not a measurement.** Neither query has
  been evaluated against a real database from this checkout. There is no measured
  false-positive rate and no measured false-negative rate; the precision tag reflects the
  known approximations above, not observed output.
- **Validated against one operator plus a synthetic test.** `github.com/humio/humio-operator`,
  by reading query output, and the fixtures under `test/`. The tests pin specific behaviours
  — container traversal through slices, arrays and map values; named string types and
  `[]byte`; the `metav1` and unregistered-base exclusions — on hand-written Go that was
  written to exercise them. That is regression cover, not evidence about real operators.
  Treat both queries as leads to investigate, not as verdicts.

## Layout

```
codeql-workspace.yml            ties src/ and test/ together; `codeql test run` needs it
src/
├── qlpack.yml                  hoeg/k8s-operators, depends on codeql/go-all ^7.3.0
├── codeql-pack.lock.yml        committed on purpose
├── K8sOperators.qll            the one shared library, imported as `import K8sOperators`
├── codeql-suites/k8s-operators.qls
├── Security/CWE-200/K8sSecretsLeak.ql            (+ .qhelp)
├── Security/CWE-089/K8sCustomResourceSqlInjection.ql  (+ .qhelp)
└── Exploration/                seven no-metadata debugging queries
test/
├── qlpack.yml                  hoeg/k8s-operators-tests, depends on src/ via ${workspace}
└── <QueryName>/                one directory per query test:
                                test.go + vendored k8s types, .qlref, .expected
.github/workflows/ci.yml        pack-install verify, format, compile, test, pack resolution
```

## License

MIT. See `LICENSE`.
