@id("ADMIN:read")
permit(principal, action == Action::"read", resource)
  when { (principal.role == "admin") };

@id("P_ctx:read")
forbid(principal, action == Action::"read", resource)
  when { ((context.risk >= 70) && (!(principal.role == "admin"))) };

@id("P1:read")
forbid(principal, action == Action::"read", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:read")
forbid(principal, action == Action::"read", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:read")
permit(principal, action == Action::"read", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P3:read")
permit(principal, action == Action::"read", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P4:read")
permit(principal, action == Action::"read", resource)
  when { ((((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("read"))) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P6:read")
permit(principal, action == Action::"read", resource)
  when { ((context.del.contains("read")) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P5:read")
forbid(principal, action == Action::"read", resource)
  when { ((principal.role == "analyst") && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (!(((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("read")))) && (!(context.del.contains("read")))) };

@id("ADMIN:write")
permit(principal, action == Action::"write", resource)
  when { (principal.role == "admin") };

@id("P_ctx:write")
forbid(principal, action == Action::"write", resource)
  when { ((context.risk >= 70) && (!(principal.role == "admin"))) };

@id("P1:write")
forbid(principal, action == Action::"write", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:write")
forbid(principal, action == Action::"write", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:write")
permit(principal, action == Action::"write", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P3:write")
permit(principal, action == Action::"write", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P4:write")
permit(principal, action == Action::"write", resource)
  when { ((((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("write"))) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P6:write")
permit(principal, action == Action::"write", resource)
  when { ((context.del.contains("write")) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P5:write")
forbid(principal, action == Action::"write", resource)
  when { ((principal.role == "analyst") && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (!(((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("write")))) && (!(context.del.contains("write")))) };

@id("ADMIN:download")
permit(principal, action == Action::"download", resource)
  when { (principal.role == "admin") };

@id("P_ctx:download")
forbid(principal, action == Action::"download", resource)
  when { ((context.risk >= 70) && (!(principal.role == "admin"))) };

@id("P1:download")
forbid(principal, action == Action::"download", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:download")
forbid(principal, action == Action::"download", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:download")
permit(principal, action == Action::"download", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P3:download")
permit(principal, action == Action::"download", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P4:download")
permit(principal, action == Action::"download", resource)
  when { ((((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("download"))) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P6:download")
permit(principal, action == Action::"download", resource)
  when { ((context.del.contains("download")) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P5:download")
forbid(principal, action == Action::"download", resource)
  when { ((principal.role == "analyst") && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (!(((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("download")))) && (!(context.del.contains("download")))) };

@id("ADMIN:delete")
permit(principal, action == Action::"delete", resource)
  when { (principal.role == "admin") };

@id("P_ctx:delete")
forbid(principal, action == Action::"delete", resource)
  when { ((context.risk >= 70) && (!(principal.role == "admin"))) };

@id("P1:delete")
forbid(principal, action == Action::"delete", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:delete")
forbid(principal, action == Action::"delete", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:delete")
permit(principal, action == Action::"delete", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P3:delete")
permit(principal, action == Action::"delete", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div)) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P4:delete")
permit(principal, action == Action::"delete", resource)
  when { ((((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("delete"))) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P6:delete")
permit(principal, action == Action::"delete", resource)
  when { ((context.del.contains("delete")) && (!(context.risk >= 70)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (principal.clr < resource.sens)))) };

@id("P5:delete")
forbid(principal, action == Action::"delete", resource)
  when { ((principal.role == "analyst") && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && (principal has div && resource has div && principal.div == resource.div))) && (!(((principal.role == "analyst") || (principal.role == "division_manager")) && (principal.dept == resource.dept) && (context.asg.contains("delete")))) && (!(context.del.contains("delete")))) };