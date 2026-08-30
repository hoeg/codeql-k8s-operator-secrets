/**
 * Exploration: writes to fields of the struct types declared for registered
 * custom resources.
 */

import go
import K8sOperators

from
  TypeDecl td, TypeSpec ts, CustomResourceType crt, StructTypeExpr ste, Field f, Write w,
  StructType st
where
  td.getASpec() = ts and
  ts.getName() = crt.getName() and
  ste = ts.getAChildExpr() and
  ste.getType() = st and
  f = st.getField(_) and
  w = f.getAWrite()
select w.getLhs(), w.getRhs()
// lifted example from the web to help with finding writes
// Writes to Url field
/*
 * from Field f, Write write, StructType stt, StructTypeExpr ste
 * where
 *  stt.hasField("Url", _)
 *  and ste.getType() = stt
 *  and stt.getField("Url") = f
 *  and write = f.getAWrite()
 * select write.getRhs()
 */

