// Write tools carry caller_username. It must be the signed-in user from the token, never a value the model chose.
forbid (
    principal,
    action in [AgentCore::Action::"HelpdeskTools___reset_mfa", AgentCore::Action::"HelpdeskTools___send_email"],
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
)
unless {
    principal.hasTag("username") &&
    context.input has caller_username &&
    context.input.caller_username == principal.getTag("username")
};
