// A refund is a positive amount in USD, never more than the order cost.
@id("refund_amount_sane")
forbid (principal, action == TSG::Action::"issue_refund", resource is TSG::Order)
unless {
    context.input.amount_cents > 0 &&
    context.input.currency == "USD" &&
    context.input.amount_cents <= resource.total_cents
};
