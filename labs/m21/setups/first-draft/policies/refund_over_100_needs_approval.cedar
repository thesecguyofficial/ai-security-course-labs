// FIRST DRAFT. Support agents need an approval for refunds over $100. Supervisors don't.
// The model is told to add approval_id once a supervisor has approved. The PEP checks the ID exists.
@id("refund_over_100_needs_approval")
@on_deny("defer")
forbid (principal, action == TSG::Action::"issue_refund", resource)
when { principal.role != "supervisor" && context.input.amount_cents > 10000 }
unless { context.input has approval_id };
