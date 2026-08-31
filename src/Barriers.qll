/**
 * Barriers (taint-tracking sanitizers) shared by the Kubernetes-operator queries
 * in this pack.
 *
 * Two independent families of barrier live here:
 *
 * - `guardedEnvVarValueRead`: a read of `EnvVar.Value` that is control-dependent
 *   on an equality test against `EnvVar.Name` on the same base. Container
 *   environment is modelled as a flat `[]corev1.EnvVar`, and the data-flow
 *   library does not correlate the `Name` and `Value` fields of a slice element,
 *   so appending one `EnvVar` taints the `Value` of *every* element read later.
 *   A name check re-establishes the correlation the model lost.
 *
 * - `formatVerbBarrierArgument`: an argument of a `fmt` formatting call whose
 *   corresponding verb is `%T` (prints a type name, not the value) or `%w`
 *   (wraps an error). `%v`, `%s` and `%q` are deliberately left propagating.
 *
 * Nothing in this file is `private`: it exists to be imported by the queries and
 * by tests.
 */

import go

/**
 * Gets a data-flow node that reads the field `fieldName` of a
 * `k8s.io/api/core/v1.EnvVar` value.
 *
 * Only the `EnvVar` struct from the upstream core API is matched; an operator's
 * own struct that happens to have `Name`/`Value` fields is not.
 */
DataFlow::FieldReadNode envVarFieldRead(string fieldName) {
  result.getField().hasQualifiedName("k8s.io/api/core/v1", "EnvVar", fieldName)
}

/**
 * Gets the data-flow node that `read` reads its field from, looking through an
 * implicit pointer dereference.
 *
 * `DataFlow::FieldReadNode.getBase()` returns the dereference node for a read
 * through a `*EnvVar`, which is never a use of an SSA variable; stepping to the
 * dereference operand is what makes `p.Name` and `p.Value` share a base.
 */
DataFlow::Node envVarFieldReadBase(DataFlow::FieldReadNode read) {
  result = read.getBase()
  or
  result = read.getBase().(DataFlow::PointerDereferenceNode).getOperand()
}

/**
 * Holds if `nameRead` reads `EnvVar.Name` and `valueRead` reads `EnvVar.Value`
 * from the same underlying value.
 *
 * "The same underlying value" means the two reads share an SSA-with-fields
 * access path, so `envVar.Name`/`envVar.Value` and `c.Env0.Name`/`c.Env0.Value`
 * are related, but `list[i].Name`/`list[i].Value` are not: an index step is not
 * part of a Go SSA access path, so indexed element reads are outside this
 * relation and are never barriered.
 */
predicate envVarNameAndValueReadOfSameBase(
  DataFlow::FieldReadNode nameRead, DataFlow::FieldReadNode valueRead
) {
  nameRead = envVarFieldRead("Name") and
  valueRead = envVarFieldRead("Value") and
  exists(SsaWithFields base |
    base.getAUse() = envVarFieldReadBase(nameRead) and
    base.getAUse() = envVarFieldReadBase(valueRead)
  )
}

/**
 * Holds if `guard` is the true-successor of an equality test one of whose
 * operands is `nameRead`, a read of `EnvVar.Name`.
 *
 * This covers `if envVar.Name == s3.AWSCABundle { ... }` and, because
 * `ConditionGuardNode.ensuresEq` follows `!`, `&&` and `||`, also
 * `if a && envVar.Name == x { ... }`. It does *not* require the other operand to
 * be a compile-time constant: any equality test pins `Name` to one value on the
 * guarded branch, which is what makes the `Name`/`Value` correlation hold again.
 * Comparing against another non-constant read (`override.Name == base.Name`) is
 * therefore also accepted; it correlates the two `EnvVar`s rather than pinning
 * either to a literal, which is still enough to break the spurious flow.
 */
predicate envVarNameEqualityGuard(
  ControlFlow::ConditionGuardNode guard, DataFlow::FieldReadNode nameRead
) {
  nameRead = envVarFieldRead("Name") and
  guard.ensuresEq(nameRead, _)
}

/**
 * Holds if `entry` is the control-flow node at which the body of a `case` clause
 * of `switch <nameRead> { ... }` starts, where `nameRead` reads `EnvVar.Name`.
 *
 * A tagged `switch` produces no `ConditionGuardNode` in the Go CFG — condition
 * guards are only built for boolean branch conditions, and a tagged switch's
 * case expressions are values — so the case-test-passing edge is used instead.
 */
predicate envVarNameSwitchCaseEntry(ControlFlow::Node entry, DataFlow::FieldReadNode nameRead) {
  nameRead = envVarFieldRead("Name") and
  ControlFlow::isSwitchCaseTestPassingEdge(_, entry, nameRead.asExpr(), _)
}

/**
 * Holds if `valueRead` reads `EnvVar.Value` at a program point that is only
 * reachable when an equality test against `EnvVar.Name` on the same base has
 * succeeded.
 *
 * Both guard forms are recognised:
 *
 * ```go
 * for _, envVar := range c.Env {
 *   if envVar.Name == s3.AWSCABundleConfigMap { name = envVar.Value }  // `if` form
 *   switch envVar.Name {
 *   case s3.AWSCABundle: path = envVar.Value                           // `switch` form
 *   }
 * }
 * ```
 *
 * This is the precise, guard-based formulation: it uses
 * `ControlFlow::ConditionGuardNode.dominates` for the `if` form and basic-block
 * dominance of the case body for the `switch` form, rather than the looser
 * "some comparison on `Name` dominates this block" approximation.
 *
 * It over-approximates in one direction: the guarded value is only known to
 * equal *something*, so a comparison against another tainted string still
 * produces a barrier. It under-approximates whenever the two reads do not share
 * an SSA access path (see `envVarNameAndValueReadOfSameBase`), when the guard is
 * a `strings.EqualFold`-style call rather than `==`, and when the `Value` read is
 * merely post-dominated rather than dominated by the check.
 */
predicate guardedEnvVarValueRead(DataFlow::FieldReadNode valueRead) {
  exists(DataFlow::FieldReadNode nameRead | envVarNameAndValueReadOfSameBase(nameRead, valueRead) |
    exists(ControlFlow::ConditionGuardNode guard |
      envVarNameEqualityGuard(guard, nameRead) and
      guard.dominates(valueRead.getBasicBlock())
    )
    or
    exists(ControlFlow::Node entry |
      envVarNameSwitchCaseEntry(entry, nameRead) and
      entry.getBasicBlock().dominates(valueRead.getBasicBlock())
    )
  )
}

/**
 * Gets a data-flow node that is a barrier because it reads `EnvVar.Value` under
 * a check on the corresponding `EnvVar.Name`.
 *
 * Intended for use in an `isBarrier`/`isSanitizer` member predicate.
 */
DataFlow::Node getAGuardedEnvVarValueRead() { guardedEnvVarValueRead(result) }

/**
 * Gets the 0-based index of the format-string parameter of the `fmt` function
 * `f`, for the `fmt` functions that take one.
 *
 * `fmt.Sprint`, `fmt.Sprintln`, `fmt.Print` and friends are absent on purpose:
 * they have no format string, so no verb can be attributed to their arguments
 * and they always propagate taint.
 */
int fmtFormatArgumentIndex(Function f) {
  f.hasQualifiedName("fmt", ["Errorf", "Sprintf", "Printf"]) and result = 0
  or
  f.hasQualifiedName("fmt", ["Fprintf", "Appendf"]) and result = 1
}

/**
 * Holds if `call` is a call to a `fmt` formatting function whose format string
 * is the constant `format`, passed as argument `formatIndex`.
 *
 * Calls that spread a slice (`fmt.Errorf(f, args...)`) are excluded: there is no
 * argument-to-verb correspondence to compute.
 *
 * The `strictcount` is a soundness guard, not a filter that does work: it stops
 * an expression with two possible constant values from letting one string's
 * `%T` be attributed to the other's `%v` argument. On every database this was
 * measured against (kserve, external-secrets, cert-manager, k8s-config-connector)
 * no format argument has more than one constant value, so this conjunct is
 * unexercised — removing it changes no result anywhere it has been tested.
 */
predicate fmtFormatCall(CallExpr call, int formatIndex, string format) {
  formatIndex = fmtFormatArgumentIndex(call.getTarget()) and
  not call.hasEllipsis() and
  format = call.getArgument(formatIndex).getStringValue() and
  strictcount(call.getArgument(formatIndex).getStringValue()) = 1
}

/** Holds if `format` is the constant format string of some `fmt` formatting call. */
predicate fmtFormatString(string format) { fmtFormatCall(_, _, format) }

/**
 * Gets the length of the maximal run of consecutive `%` characters in `format`
 * that ends at index `i`.
 *
 * Runs are what distinguish an escaped `%%` from a directive: in `%%%T` the
 * first two `%` are an escape and the third opens a directive.
 */
int percentRunLength(string format, int i) {
  fmtFormatString(format) and
  format.charAt(i) = "%" and
  (
    not format.charAt(i - 1) = "%" and result = 1
    or
    format.charAt(i - 1) = "%" and result = percentRunLength(format, i - 1) + 1
  )
}

/**
 * Holds if index `i` of `format` opens a formatting directive, that is, a `%`
 * that is not part of a `%%` escape.
 */
predicate directiveStart(string format, int i) {
  percentRunLength(format, i) % 2 = 1 and
  not format.charAt(i + 1) = "%"
}

/**
 * Holds if `c` is a character that may appear inside a directive between the `%`
 * and the verb letter: a flag, a width or precision digit, a `*`, the `.`
 * separating width from precision, or a bracket delimiting an explicit argument
 * index.
 */
predicate formatSpecChar(string c) {
  c =
    ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "-", "#", " ", ".", "*", "[", "]", "'"]
}

/**
 * Gets the index of the verb character of the directive that starts at index `i`
 * of `format`: the first character after the `%` that cannot be part of the
 * flags, width, precision or explicit argument index.
 *
 * Has no result for a `%` at the very end of the string, which makes such a
 * directive unsupported (see `unsupportedDirective`).
 */
int verbIndex(string format, int i) {
  directiveStart(format, i) and
  result =
    min(int j | j in [i + 1 .. format.length() - 1] and not formatSpecChar(format.charAt(j)) | j)
}

/** Gets the verb character of the directive that starts at index `i` of `format`. */
string directiveVerb(string format, int i) { result = format.charAt(verbIndex(format, i)) }

/**
 * Gets the text of the directive that starts at index `i` of `format` between
 * the `%` and the verb: its flags, explicit argument index, width and precision.
 */
string directiveSpec(string format, int i) {
  directiveStart(format, i) and
  result = format.substring(i + 1, verbIndex(format, i))
}

/** Gets the number of occurrences of the character `c` in `s`. */
bindingset[s, c]
int charCount(string s, string c) {
  result = count(int i | i in [0 .. s.length() - 1] and s.charAt(i) = c | i)
}

/**
 * Gets the explicit argument index `n` of a directive written `%[n]v`, if it has
 * one. The index is 1-based, as in Go.
 */
int directiveExplicitIndex(string format, int i) {
  result = directiveSpec(format, i).regexpCapture("[^\\[\\]]*\\[([0-9]+)\\][^\\[\\]]*", 1).toInt()
}

/**
 * Gets the number of `*` width/precision placeholders in the directive starting
 * at index `i` of `format`. Each consumes one argument ahead of the verb's own.
 */
int directiveStarCount(string format, int i) { result = charCount(directiveSpec(format, i), "*") }

/**
 * Holds if the directive starting at index `i` of `format` uses a feature this
 * library does not model:
 *
 * - a `%` with nothing but flag, width and precision characters after it, so the
 *   directive has no verb at all (`"leaked %T %"`);
 * - a verb that is not a letter, which means the string is malformed — most
 *   often an unescaped percent sign, as in `"100% %T"`, where Go reads the space
 *   as a flag and then trips over the second `%`;
 * - more than one bracketed argument index in a single directive (`%[3]*[2]d`,
 *   where each `*` may be re-indexed independently).
 *
 * A format string containing such a directive is dropped wholesale by
 * `supportedFormatString`, because one mis-modelled directive shifts the
 * argument numbering of every directive after it, and a shifted numbering could
 * attribute a `%T` to an argument that is really printed by a `%v`.
 */
predicate unsupportedDirective(string format, int i) {
  directiveStart(format, i) and
  (
    not exists(verbIndex(format, i))
    or
    not directiveVerb(format, i).regexpMatch("[a-zA-Z]")
    or
    charCount(directiveSpec(format, i), "[") > 1
  )
}

/**
 * Holds if every directive of `format` is one whose argument consumption this
 * library models.
 */
predicate supportedFormatString(string format) {
  fmtFormatString(format) and
  not unsupportedDirective(format, _)
}

/**
 * Gets the 1-based position of the directive starting at index `i` among the
 * directives of `format`, in left-to-right order.
 */
int directiveRank(string format, int i) { i = rank[result](int j | directiveStart(format, j) | j) }

/**
 * Gets the 1-based number of the first argument available to the directive
 * starting at index `i` of `format`, before its own explicit index and `*`
 * placeholders are taken into account.
 */
int directiveFirstArgNumber(string format, int i) {
  directiveRank(format, i) = 1 and result = 1
  or
  exists(int prev |
    directiveRank(format, prev) = directiveRank(format, i) - 1 and
    result = directiveArgNumber(format, prev) + 1
  )
}

/**
 * Gets the 1-based number of the argument formatted by the verb of the directive
 * starting at index `i` of `format`.
 *
 * The model is: an explicit `[n]` index resets the argument counter to `n`; then
 * each `*` placeholder consumes one argument; then the verb consumes the next
 * one; the following directive resumes from there. This matches Go for
 * `%v`, `%[2]v`, `%*d` and `%[2]*d`, and is only approximate for the rare
 * multiply-indexed form that `unsupportedDirective` filters out anyway.
 */
int directiveArgNumber(string format, int i) {
  exists(int base |
    base = directiveExplicitIndex(format, i)
    or
    not exists(directiveExplicitIndex(format, i)) and base = directiveFirstArgNumber(format, i)
  |
    result = base + directiveStarCount(format, i)
  )
}

/**
 * Holds if `arg` is passed to the `fmt` formatting `call` at a syntactic
 * argument position whose corresponding verb is `verb`.
 *
 * Syntactic positions are used deliberately: a variadic call bundles its
 * trailing arguments into one implicit slice, so `DataFlow::CallNode.getArgument`
 * returns that single slice for every one of them and could not distinguish the
 * `%T` argument from the `%v` one.
 */
predicate fmtFormattedArgument(CallExpr call, DataFlow::Node arg, string verb) {
  exists(int formatIndex, string format, int i |
    fmtFormatCall(call, formatIndex, format) and
    supportedFormatString(format) and
    directiveStart(format, i) and
    verb = directiveVerb(format, i) and
    arg = DataFlow::exprNode(call.getArgument(formatIndex + directiveArgNumber(format, i)))
  )
}

/**
 * Holds if `arg` is an argument of a `fmt` formatting call whose corresponding
 * verb is `%T` or `%w`, and so does not put the argument's own contents into the
 * formatted result.
 *
 * `%T` prints the argument's Go type name, which carries no value. `%w` records
 * the argument as a wrapped error for `errors.Is`/`errors.As`. Treating `%w` as
 * a barrier is a deliberate precision trade-off rather than a strict truth:
 * `Error()` on the wrapping error does concatenate the wrapped error's message,
 * so a secret already inside that message is still reachable through the
 * wrapper. What it buys is that long `if err != nil { return fmt.Errorf("...: %w", err) }`
 * chains stop being reported as fresh flow, which is where most of the
 * unreviewable multi-hop paths in this pack came from.
 */
predicate formatVerbBarrierArgument(DataFlow::Node arg) { fmtFormattedArgument(_, arg, ["T", "w"]) }

/**
 * Gets an argument of a `fmt` formatting call whose corresponding verb is `%T`
 * or `%w`.
 *
 * Intended for use in an `isBarrier`/`isSanitizer` member predicate.
 */
DataFlow::Node getAFormatVerbBarrierArgument() { formatVerbBarrierArgument(result) }

/**
 * Gets an argument of a `fmt` formatting call whose corresponding verb is `%T`.
 *
 * This is the half of `getAFormatVerbBarrierArgument` that is unconditionally
 * sound: `%T` formats the argument's type name and never its contents. Use it
 * instead of `getAFormatVerbBarrierArgument` in a configuration that must not
 * lose secrets carried inside a wrapped error's message.
 */
DataFlow::Node getATypeVerbFormattedArgument() { fmtFormattedArgument(_, result, "T") }

/**
 * Gets an argument of a `fmt` formatting call whose corresponding verb is `%w`.
 *
 * Separated out because, unlike `%T`, this one trades recall for triage cost:
 * see `formatVerbBarrierArgument` for what it can hide.
 */
DataFlow::Node getAWrapVerbFormattedArgument() { fmtFormattedArgument(_, result, "w") }
