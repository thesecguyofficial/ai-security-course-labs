// The break-glass admin is never reset through the agent, whoever asks.
forbid (
    principal,
    action == AgentCore::Action::"HelpdeskTools___reset_mfa",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when { context.input.target_username == "breakglass-admin" };
