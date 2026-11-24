@id("ADMIN:read")
permit(principal, action == Action::"read", resource)
  when { (principal.role == "admin") };

@id("P1:read")
forbid(principal, action == Action::"read", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:read")
forbid(principal, action == Action::"read", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:read")
permit(principal, action == Action::"read", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P3:read")
permit(principal, action == Action::"read", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div)))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P4:read")
permit(principal, action == Action::"read", resource)
  when { (((!context.asg.isEmpty()) && (context.asg.contains("read")) && ((principal.role == "analyst") || (principal.role == "division_manager"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P5:read")
forbid(principal, action == Action::"read", resource)
  when { (((principal.role == "analyst") && (!(!context.asg.isEmpty()))) && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (!((!context.asg.isEmpty()) && (context.asg.contains("read")) && ((principal.role == "analyst") || (principal.role == "division_manager"))))) };

@id("P6:read")
permit(principal, action == Action::"read", resource)
  when { (((!context.del.isEmpty()) && (context.del.contains("read"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens))) && (!((principal.role == "analyst") && (!(!context.asg.isEmpty()))))) };

@id("ADMIN:write")
permit(principal, action == Action::"write", resource)
  when { (principal.role == "admin") };

@id("P1:write")
forbid(principal, action == Action::"write", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:write")
forbid(principal, action == Action::"write", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:write")
permit(principal, action == Action::"write", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P3:write")
permit(principal, action == Action::"write", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div)))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P4:write")
permit(principal, action == Action::"write", resource)
  when { (((!context.asg.isEmpty()) && (context.asg.contains("write")) && ((principal.role == "analyst") || (principal.role == "division_manager"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P5:write")
forbid(principal, action == Action::"write", resource)
  when { (((principal.role == "analyst") && (!(!context.asg.isEmpty()))) && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (!((!context.asg.isEmpty()) && (context.asg.contains("write")) && ((principal.role == "analyst") || (principal.role == "division_manager"))))) };

@id("P6:write")
permit(principal, action == Action::"write", resource)
  when { (((!context.del.isEmpty()) && (context.del.contains("write"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens))) && (!((principal.role == "analyst") && (!(!context.asg.isEmpty()))))) };

@id("ADMIN:download")
permit(principal, action == Action::"download", resource)
  when { (principal.role == "admin") };

@id("P1:download")
forbid(principal, action == Action::"download", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:download")
forbid(principal, action == Action::"download", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:download")
permit(principal, action == Action::"download", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P3:download")
permit(principal, action == Action::"download", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div)))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P4:download")
permit(principal, action == Action::"download", resource)
  when { (((!context.asg.isEmpty()) && (context.asg.contains("download")) && ((principal.role == "analyst") || (principal.role == "division_manager"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P5:download")
forbid(principal, action == Action::"download", resource)
  when { (((principal.role == "analyst") && (!(!context.asg.isEmpty()))) && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (!((!context.asg.isEmpty()) && (context.asg.contains("download")) && ((principal.role == "analyst") || (principal.role == "division_manager"))))) };

@id("P6:download")
permit(principal, action == Action::"download", resource)
  when { (((!context.del.isEmpty()) && (context.del.contains("download"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens))) && (!((principal.role == "analyst") && (!(!context.asg.isEmpty()))))) };

@id("ADMIN:delete")
permit(principal, action == Action::"delete", resource)
  when { (principal.role == "admin") };

@id("P1:delete")
forbid(principal, action == Action::"delete", resource)
  when { (((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty()))) && (!(principal.role == "admin"))) };

@id("P_class:delete")
forbid(principal, action == Action::"delete", resource)
  when { (((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)) && (!(principal.role == "admin"))) };

@id("P2:delete")
permit(principal, action == Action::"delete", resource)
  when { (((principal.role == "director") && (principal.dept == resource.dept)) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P3:delete")
permit(principal, action == Action::"delete", resource)
  when { (((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div)))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P4:delete")
permit(principal, action == Action::"delete", resource)
  when { (((!context.asg.isEmpty()) && (context.asg.contains("delete")) && ((principal.role == "analyst") || (principal.role == "division_manager"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens)))) };

@id("P5:delete")
forbid(principal, action == Action::"delete", resource)
  when { (((principal.role == "analyst") && (!(!context.asg.isEmpty()))) && (!(principal.role == "admin")) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (!((!context.asg.isEmpty()) && (context.asg.contains("delete")) && ((principal.role == "analyst") || (principal.role == "division_manager"))))) };

@id("P6:delete")
permit(principal, action == Action::"delete", resource)
  when { (((!context.del.isEmpty()) && (context.del.contains("delete"))) && (!((!(principal.dept == resource.dept)) && (!(!context.del.isEmpty())))) && (!((resource.sens > 0) && (!((principal.role == "director") && (principal.dept == resource.dept))) && (!((principal.role == "division_manager") && (principal.dept == resource.dept) && ((principal has div && resource has div && principal.div == resource.div) || (!(principal has div) && !(resource has div))))) && (principal.clr < resource.sens))) && (!((principal.role == "analyst") && (!(!context.asg.isEmpty()))))) };