// The agent may email the person who raised the ticket, and nobody else.
@id("email_ticket_requester_only")
permit (principal, action == TSG::Action::"send_email", resource is TSG::Ticket)
when {
    ["support", "supervisor", "contractor"].contains(principal.role) &&
    context.input.to == resource.requester
};
