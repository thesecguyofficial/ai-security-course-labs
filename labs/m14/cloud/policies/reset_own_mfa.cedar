// reset_mfa on your own account.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___reset_mfa",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when {
    principal.hasTag("username") &&
    context.input.target_username == principal.getTag("username")
};
