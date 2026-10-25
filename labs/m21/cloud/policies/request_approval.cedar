// Guided build. Anyone signed in may ASK for an approval, as themselves. Asking moves no money.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"RefundTools___request_refund_approval",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when {
    principal.hasTag("username") &&
    context.input.caller_username == principal.getTag("username")
};
