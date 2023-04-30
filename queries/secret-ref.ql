import go

private class TypePlan extends Type {
  TypePlan(){
	//Consider if we should use hasQualifiedName instead?
    this.getName() = "SecretKeySelector"
  }
}

from StructTypeExpr ste, StructType st, PointerType pt, FieldBase f
where st.hasField(_, pt) 
  and pt.getBaseType() instanceof TypePlan 
  and ste.getType() = st
  and ste.getAField() = f
select ste.getLocation()
