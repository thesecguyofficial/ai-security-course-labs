// The agent may send email for the signed-in user. Challenge 1: add a forbid policy for addresses outside example.com.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___send_email",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
)
when { principal.hasTag("username") };
