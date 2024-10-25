/**
 * @name Exposing secret values in k8s custom resources
 * @description A secret value is assigned to a variable of a kubernetes custom resource
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10
 * @precision high
 * @id go/k8s-secrets-leak
 * @tags security
 *       external/cwe/cwe-200
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

private class APISchemaBuilder extends Function {
  APISchemaBuilder() {
    this.getName() = "AddKnownTypes"
    and 
    this.getPackage().getPath() = "k8s.io/apimachinery/pkg/runtime"
  }
} 

private class CustomResourceType extends Type {
  CustomResourceType() {
    exists(CallExpr ce | 
      (ce.getTarget() instanceof SchemaBuilder)// or ce.getTarget() instanceof APISchemaBuilder)
      and this = ce.getAnArgument().getType().(PointerType).getBaseType()
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
  select sink.getNode(), source, sink, "Secret value is leaked in Custom Resource"

