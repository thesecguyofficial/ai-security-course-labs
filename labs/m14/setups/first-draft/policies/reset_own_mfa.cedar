// Written, tested in LOG_ONLY, never promoted: the gateway still runs in LOG_ONLY mode.
forbid (
    principal,
    action == AgentCore::Action::"HelpdeskTools___reset_mfa",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
)
unless { context.input.target_username == context.input.caller_username };
