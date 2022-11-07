import go

/*
		addedAction, err := r.HumioClient.AddAction(config, req, ha)
		if err != nil {
			return reconcile.Result{}, r.logErrorAndReturn(err, "could not create action")
		}
		r.Log.Info("Created action", "Action", ha.Spec.Name)

		result, err := r.reconcileHumioActionAnnotations(ctx, addedAction, ha, req)
*/

private class Source extends DataFlow::Node {
  Source() {
    exists(DefineStmt ds | ds.getAnLhs() and this.)
  }
}

private class Sink extends DataFlow::Node {
  Sink() {
    exists(Assignment a | a.getAChildExpr() = this.asExpr())
  }
}

class Configuration extends TaintTracking::Configuration {
  Configuration() {this = "TaintTest"}

  override predicate isSource(DataFlow::Node source) {source instanceof Source}

  override predicate isSink(DataFlow::Node sink) {sink instanceof Sink}
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select source, sink