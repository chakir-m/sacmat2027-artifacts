// CHAIN-9 repaired (C9_FIX), written idiomatically for Cedar's forbid-overrides semantics.
// Platform administrators are exempted with `unless`; everything else needs a permit.

// P_ctx: risk-based context deny
@id("P_ctx")
forbid (principal, action, resource)
  when { context.risk >= 70 } unless { principal.role == "admin" };

// P1: inter-department segmentation (a delegation is the only exception)
@id("P1")
forbid (principal, action, resource)
  when { principal.dept != resource.dept && context.del.isEmpty() }
  unless { principal.role == "admin" };

// P_class: classification barrier (directors in their department, division managers
// in their own division, and owners reading or downloading inside their department are exempt)
@id("P_class")
forbid (principal, action, resource)
  when { resource.sens > 0 && principal.clr < resource.sens }
  unless { principal.role == "admin"
           || (principal.role == "director" && principal.dept == resource.dept)
           || (principal.role == "division_manager" && principal.dept == resource.dept
               && principal has div && resource has div && principal.div == resource.div)
           || (context.own && principal.dept == resource.dept
               && (action == Action::"read" || action == Action::"download")) };

@id("ADMIN")
permit (principal, action, resource) when { principal.role == "admin" };

// P2: director, own department
@id("P2")
permit (principal, action, resource)
  when { principal.role == "director" && principal.dept == resource.dept };

// P3: division manager, own division
@id("P3")
permit (principal, action, resource)
  when { principal.role == "division_manager" && principal.dept == resource.dept
         && principal has div && resource has div && principal.div == resource.div };

// P_own: the owner reads or downloads her object inside her department (phase 5)
@id("P_own")
permit (principal, action in [Action::"read", Action::"download"], resource)
  when { context.own && principal.dept == resource.dept };

// P4: assignment, same department, read only (phase 6: assignments grant read access only)
@id("P4")   permit (principal, action == Action::"read", resource)
  when { (principal.role == "analyst" || principal.role == "division_manager")
         && principal.dept == resource.dept && context.asg.contains("read") };

// P6: delegation, action in the delegation
@id("P6:read")     permit (principal, action == Action::"read", resource)     when { context.del.contains("read") };
@id("P6:write")    permit (principal, action == Action::"write", resource)    when { context.del.contains("write") };
@id("P6:download") permit (principal, action == Action::"download", resource) when { context.del.contains("download") };
@id("P6:delete")   permit (principal, action == Action::"delete", resource)   when { context.del.contains("delete") };

// P5 (analysts without a grant for the action) and P7 (default deny) are Cedar's default.
