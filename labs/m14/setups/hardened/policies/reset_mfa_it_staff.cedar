// reset_mfa on anyone's account: IT staff only. (In production, key this on a group claim; Module 20.)
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___reset_mfa",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/tsg-helpdesk-gw-a1b2c3d4e5"
)
when {
    principal.hasTag("username") &&
    ["alice"].contains(principal.getTag("username"))
};
