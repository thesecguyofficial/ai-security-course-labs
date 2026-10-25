// Support agents and supervisors may refund an order that belongs to the ticket's customer.
@id("refund_ticket_order")
permit (principal, action == TSG::Action::"issue_refund", resource is TSG::Order)
when {
    ["support", "supervisor"].contains(principal.role) &&
    resource.customer == context.ticket.requester
};
