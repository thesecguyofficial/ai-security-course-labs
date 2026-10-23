// The break-glass admin is never reset through the agent, whoever asks.
forbid (
    principal,
    action == AgentCore::Action::"HelpdeskTools___reset_mfa",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
)
when { context.input.target_username == "breakglass-admin" };
