// reset_mfa on anyone's account: IT staff only. (In production, key this on a group claim; Module 20.)
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"HelpdeskTools___reset_mfa",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when {
    principal.hasTag("username") &&
    ["alice"].contains(principal.getTag("username"))
};
