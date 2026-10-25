// Guided build. Support staff may refund up to $100 (10000 cents, an integer in the tool schema, so a Cedar Long),
// in USD, and only as themselves: caller_username must match the token's username claim.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"RefundTools___issue_refund",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when {
    principal.hasTag("username") &&
    ["bob", "alice"].contains(principal.getTag("username")) &&
    context.input.caller_username == principal.getTag("username") &&
    context.input.currency == "USD" &&
    context.input.amount_cents > 0 &&
    context.input.amount_cents <= 10000
};
