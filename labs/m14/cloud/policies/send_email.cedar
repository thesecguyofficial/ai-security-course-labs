// The agent may send email for the signed-in user. Challenge 1: add a forbid policy for addresses outside example.com.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___send_email",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when { principal.hasTag("username") };
