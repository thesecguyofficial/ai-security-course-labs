// Anyone signed in to the Helpdesk web app may search the IT knowledge base.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___search_kb",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when { principal.hasTag("client_id") && principal.getTag("client_id") == "WEB_CLIENT_ID" };
