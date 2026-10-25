// Look up an order only when it belongs to the customer who raised the ticket being worked.
// The customer comes from the order database (resource), the requester from the session (context.ticket):
// neither comes from the model.
@id("lookup_ticket_order")
permit (principal, action == TSG::Action::"lookup_order", resource is TSG::Order)
when {
    ["support", "supervisor", "contractor"].contains(principal.role) &&
    resource.customer == context.ticket.requester
};
