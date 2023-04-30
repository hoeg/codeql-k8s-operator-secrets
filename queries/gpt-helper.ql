/**
 * @name Database query built from user-controlled sources
 * @description Building a database query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import go
import DataFlow::PathGraph
import semmle.go.frameworks.K8sIoClientGo

private class SchemaBuilder extends Function  {
    SchemaBuilder() {
      this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme"
      and 
      this.getName() = "Register"
    }
  }
  
  //explorative using select and print AST
  private class CustomResourceType extends Type {
    CustomResourceType() {
      exists(CallExpr ce, Function f, Expr e, PointerType pt, TypeSpec ts | 
            f = ce.getTarget()
        and f instanceof SchemaBuilder
        and e = ce.getAnArgument()
        and pt = e.getType()
        and this = pt.getBaseType()
        and ts.getName() = this.getName()
      )
    }
  }

  private class KubernetesSecret extends Type {
    KubernetesSecret() {
          this.getPackage().getPath() = "k8s.io/api/core/v1" 
      and this.getName() = "Secret"
    }
  }

  private class K8sGet extends Function {
    K8sGet() {
          this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/client"
      and this.getName() = "Get" 
    }
  }


class KubernetesSecretSource extends DataFlow::Node {
  KubernetesSecretSource() {
    exists(DataFlow::CallNode call |
      call.getResult() = this and
      call.getTarget() instanceof K8sGet and
      call.getAnArgument().getType().(PointerType).getBaseType() instanceof KubernetesSecret
    )
  }
}

class K8sSecretData extends DataFlow::ReadNode {
  K8sSecretData() {
    exists(Field f, IndexExpr ie |
       ie = this.asExpr()
       and ie.getBase() = f.getARead().asExpr()
       and f.getQualifiedName() = "k8s.io/api/core/v1.Secret.Data"
    )
  }
}

class CustomResourceValueSource extends DataFlow::ReadNode {
  CustomResourceValueSource() {
    exists(Field f, CustomResourceType cr |
      isNestedFieldInCustomResource(cr, f) and
      this.readsField(_, f) and f.getType().getName() = "string"
    )
  }
}

predicate isNestedFieldInCustomResource(Type customResource, Field field) {
    exists(Type nestedType, Field parentField |
      (nestedType = parentField.getType().(PointerType).getBaseType() 
      or nestedType = parentField.getType()) and
      customResource.getField(_) = parentField and
      isNestedFieldInCustomResource(nestedType, field)
    ) or
    customResource.getField(_) = field
  }

  class CustomResourceSinkFromCall extends DataFlow::CallNode {
    CustomResourceSinkFromCall() {
      exists(Field f, CustomResourceType crt, Write w, DataFlow::Node base |
        isNestedFieldInCustomResource(crt, f) and
        w.writesField(base, f, this.getAResult()) and
        f.getType() instanceof StringType
      )
    }
  }
  

  class CustomResourceSink extends DataFlow::Node {
    CustomResourceSink() {
      exists(Field f, CustomResourceType crt, Write w |
        isNestedFieldInCustomResource(crt, f) and
        w.writesField(_, f, this) and
        f.getType() instanceof StringType
      )
    }
  }
  
class SecretToCustomResourceTaintConfiguration extends TaintTracking::Configuration {
    SecretToCustomResourceTaintConfiguration() { this = "SecretToCustomResourceTaintConfiguration" }
  
    override predicate isSource(DataFlow::Node source) {
      source instanceof K8sSecretData
    }
  
    override predicate isSink(DataFlow::Node sink) {
      sink instanceof CustomResourceSink
    }
  }
  
  from DataFlow::PathNode source, DataFlow::PathNode sink, SecretToCustomResourceTaintConfiguration cfg
  where cfg.hasFlowPath(source, sink)
  select sink.getNode(), source, sink, "msg"

