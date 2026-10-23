// First draft: "we'll tighten it later". Every tool, every caller. Attached in LOG_ONLY mode.
permit (
    principal,
    action in [AgentCore::Action::"HelpdeskTools___search_kb", AgentCore::Action::"HelpdeskTools___reset_mfa", AgentCore::Action::"HelpdeskTools___send_email"],
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
);
