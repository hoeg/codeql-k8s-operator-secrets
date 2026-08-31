/**
 * @name No Kubernetes custom resource types resolved
 * @description When `CustomResourceType` is empty, the two security queries in this pack lose
 *              different amounts of coverage: K8sCustomResourceSqlInjection loses its only source
 *              and reports nothing at all, while K8sSecretsLeak loses only its custom-resource
 *              sinks and still finds EnvVar, ConfigMap and annotation leaks. Report that
 *              explicitly, so a reader knows which zero to distrust and which results to keep.
 * @kind diagnostic
 * @id go/k8s-operators/no-custom-resource-types
 * @tags diagnostic
 */

import go
import K8sOperators

/**
 * Gets the SARIF severity level that indicates an error, matching
 * `semmle.go.DiagnosticsReporting.getErrorSeverity` in `codeql/go-all`.
 *
 * Error rather than warning: one of the two security queries is not degraded but
 * wholly inert, and the other is blind to an entire sink family. A consumer who
 * reads either silence as "clean" has been actively misled. That is a broken
 * scan.
 */
private int getErrorSeverity() { result = 2 }

/*
 * One condition is reported, not two, and the obvious second one -- "custom
 * resource types resolved, but not a single `CustomResourceFieldSink`" -- is
 * deliberately absent. Three reasons, in order of weight.
 *
 * It has never been observed. Across the 47 usable databases of the operator
 * corpus plus rancher/fleet, every database with at least one
 * `CustomResourceType` has at least four `CustomResourceFieldSink`s. The floor
 * is ricoberger/vault-secrets-operator (2 CR types, 4 sinks), then
 * litmuschaos/litmus (2, 8) and stakater/IngressMonitorController (2, 12); most
 * are in the hundreds and openkruise/kruise has 2886. The sink count is zero on
 * exactly the six databases where `CustomResourceType` is itself empty --
 * fleet, velero, wave, stakater/Reloader, kubernetes-replicator and
 * secrets-store-csi-driver -- all of which the condition below already reports.
 *
 * It would report the wrong kind of thing. This diagnostic exists to separate a
 * scan that could not look from a scan that looked and found nothing. CR types
 * present with no CR-field sink is the *second* of those: the type graph
 * resolved, the sink class was evaluated over it, and the operator simply never
 * writes a string into its own custom resource. K8sSecretsLeak's silence there
 * is a correct answer, and flagging it at error severity would invert the
 * signal this query carries.
 *
 * It is not free. As written, this query touches `CustomResourceType` and
 * nothing else. Counting `CustomResourceFieldSink` pulls in
 * `isPartOfCustomResource` over the whole type graph and every `Write` in the
 * program: measured on the three largest databases in the corpus it takes
 * evaluation from 873ms to 2.7s (kubeblocks), 1.1s to 3.1s (kruise) and 1.2s to
 * 3.2s (kubevirt). That is a threefold cost for a condition with no observed
 * instance.
 */

from string message, int severity
where
  not exists(CustomResourceType crt) and
  severity = getErrorSeverity() and
  message =
    "No Kubernetes custom resource types were resolved in this database, so every class in this " +
      "pack that is anchored on `CustomResourceType` is empty. The two security queries are hit " +
      "unequally by that, and their results have to be read differently. " +
      //
      "K8sCustomResourceSqlInjection is wholly inert here. Its only source is " +
      "`CustomResourceValueSource`, a read of a custom-resource field, so with no CR types it " +
      "has no sources at all and could not have reported anything whatever the code does. Its " +
      "zero result is the absence of sources, not the absence of vulnerabilities: discard it. " +
      //
      "K8sSecretsLeak is only half blind, and its results are NOT to be discarded. Its sources " +
      "are reads of `corev1.Secret.Data` / `StringData`, which do not involve custom resources " +
      "at all, and its sink is `SecretLeakSink`, the union of `CustomResourceFieldSink` and " +
      "`SecretMaterializationSink`. Only the first half is empty here. Leaks *into a " +
      "custom-resource field* are therefore invisible, but leaks into `corev1.EnvVar.Value`, " +
      "`corev1.ConfigMap.Data` / `BinaryData` and `metav1.ObjectMeta.Annotations` are still " +
      "found exactly as they would be on a database whose CR types did resolve, because " +
      "`SecretMaterializationSink` is pinned by field name and carries no custom-resource base " +
      "constraint. Any K8sSecretsLeak result reported alongside this diagnostic is a real " +
      "finding and must be kept; only its silence about custom-resource fields is meaningless. " +
      //
      "Either this project registers CR types through a scheme-registration shape the pack does " +
      "not model (only sigs.k8s.io/controller-runtime/pkg/scheme.Register and " +
      "k8s.io/apimachinery/pkg/runtime.Scheme.AddKnownTypes / AddKnownTypeWithName are " +
      "recognised, and types declared under k8s.io/ or sigs.k8s.io/ are deliberately excluded), " +
      "or it defines no CRDs at all. Run Exploration/FindCrRegistrations.ql to see which " +
      "registration call sites, if any, this database actually contains."
select message, severity
