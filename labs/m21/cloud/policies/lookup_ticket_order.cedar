// Guided build. Any signed-in Helpdesk user may look up an order. (The order-to-customer check needs data the
// gateway doesn't have; the lab's PEP does it locally. Lesson 21.5 explains where that check lives on AWS.)
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"RefundTools___lookup_order",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when { principal.hasTag("username") };
