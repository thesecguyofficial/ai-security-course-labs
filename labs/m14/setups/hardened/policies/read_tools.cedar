// Anyone signed in to the Helpdesk web app may search the IT knowledge base.
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___search_kb",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
)
when { principal.hasTag("client_id") && principal.getTag("client_id") == "7helpdeskweb0example0client" };
