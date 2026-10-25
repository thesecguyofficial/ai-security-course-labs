// Over $100 (10000 cents): only with an approval the PEP verified (signed, bound to these exact arguments,
// unused, unexpired), given by a supervisor who is not the person asking. @on_deny("defer") tells the PEP to
// hold the call for a human instead of refusing it outright.
@id("refund_over_100_needs_approval")
@on_deny("defer")
forbid (principal, action == TSG::Action::"issue_refund", resource is TSG::Order)
when { context.input.amount_cents > 10000 }
unless {
    context.approval.verified &&
    context.approval has approver &&
    context.approval.approver != principal &&
    context.approval.approver.role == "supervisor"
};
