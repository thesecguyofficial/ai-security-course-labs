// Write tools carry caller_username. It must be the signed-in user from the token, never a value the model chose.
forbid (
    principal,
    action in [AgentCore::Action::"HelpdeskTools___reset_mfa", AgentCore::Action::"HelpdeskTools___send_email"],
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
unless {
    principal.hasTag("username") &&
    context.input has caller_username &&
    context.input.caller_username == principal.getTag("username")
};
