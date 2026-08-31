// Package operator is the fixture for guardedEnvVarValueRead in Barriers.qll.
//
// This directory tests the *predicate* directly rather than through a query, so
// each case is one line of output and a case that should not be a barrier is
// visible as an absence at a named line rather than as a missing path in a
// hundred-line path-problem .expected. The end-to-end wiring -- that
// K8sSecretsLeak.ql actually installs this predicate as a barrier, and that
// taint really reaches these reads in the first place -- is tested separately in
// test/K8sSecretsLeak (noLeakGuardedEnvVarIfRead, noLeakGuardedEnvVarSwitchRead
// and their negative control leakUnguardedEnvVarRead). Neither test replaces the
// other: a probe on the predicate does not prove the query wires it up, and the
// end-to-end fixtures cannot cheaply cover the shapes below that carry no taint.
package operator

import corev1 "k8s.io/api/core/v1"

// envName is the constant the guards compare against. The barrier does not
// require a constant -- see envVarNameEqualityGuard -- but this is the shape
// operators write (`if envVar.Name == s3.AWSCABundle`).
const envName = "X"

func use(string) {}

// BARRIER: the `if` form. The equality test produces a
// ControlFlow::ConditionGuardNode whose true-successor dominates the block of
// the Value read.
func ifGuard(c *corev1.Container) {
	for _, e := range c.Env {
		if e.Name == envName {
			use(e.Value)
		}
	}
}

// BARRIER: the tagged-`switch` form, in both of its case bodies.
//
// A tagged switch produces no ConditionGuardNode at all -- condition guards are
// built only for boolean branch conditions, and a tagged switch's case
// expressions are values -- so this shape is reached by the
// isSwitchCaseTestPassingEdge disjunct and by nothing else.
func switchGuard(c *corev1.Container) {
	for _, e := range c.Env {
		switch e.Name {
		case envName:
			use(e.Value)
		case "Y":
			use(e.Value)
		}
	}
}

// BARRIER: the base is a *corev1.EnvVar, so the two field reads go through an
// implicit dereference. DataFlow::FieldReadNode.getBase() returns that
// dereference node, which is not a use of an SSA variable, so without the
// PointerDereferenceNode step in envVarFieldReadBase the two reads would not
// share a base and this would not be barriered.
func pointerBase(p *corev1.EnvVar) {
	if p.Name == envName {
		use(p.Value)
	}
}

// BARRIER: the Value read sits in the right-hand side of the `&&` whose
// left-hand side is the name test. ConditionGuardNode.ensuresEq looks through
// `&&`, so the short-circuit is understood as a guard.
func andGuard(e corev1.EnvVar) bool {
	return e.Name == envName && e.Value != ""
}

// NOT a barrier: the name test is on a different EnvVar than the value read.
// This is what stops the barrier from degenerating into "some EnvVar name was
// tested somewhere in this function".
func crossBase(a corev1.EnvVar, b corev1.EnvVar) {
	if a.Name == envName {
		use(b.Value)
	}
}

// NOT a barrier: no name test at all. The negative control for every case
// above -- a barrier that sanitised every EnvVar.Value read would still pass
// them, and would fail here.
func unguarded(c *corev1.Container) {
	for _, e := range c.Env {
		use(e.Value)
	}
}

// NOT a barrier: the test happens after the read, so the guard does not dominate
// it.
func guardTooLate(e corev1.EnvVar) {
	use(e.Value)
	if e.Name == envName {
		use("later")
	}
}

// NOT a barrier: the guard is on the false branch, where Name is known to be
// anything *but* envName, which correlates nothing.
func negatedGuard(e corev1.EnvVar) {
	if e.Name != envName {
		use(e.Value)
	}
}

// NOT a barrier: the read sits after the switch, so no case body dominates it.
// This is the switch counterpart of guardTooLate and pins the dominance test in
// the isSwitchCaseTestPassingEdge disjunct: drop it and every read anywhere
// after a switch on a Name would be sanitised.
func switchThenRead(e corev1.EnvVar) {
	switch e.Name {
	case envName:
		use("in case")
	}
	use(e.Value)
}

// notAnEnvVar is a look-alike: same field names, same field types as
// corev1.EnvVar minus ValueFrom.
type notAnEnvVar struct {
	Name  string
	Value string
}

// NOT a barrier: the identical guard shape on a struct that is not
// corev1.EnvVar. envVarFieldRead pins the field by qualified name, so an
// operator's own Name/Value struct is not sanitised on the strength of resembling
// one.
func lookAlike(x notAnEnvVar) {
	if x.Name == envName {
		use(x.Value)
	}
}
