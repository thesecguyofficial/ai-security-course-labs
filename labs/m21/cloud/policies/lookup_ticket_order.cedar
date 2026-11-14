// Guided build. Any signed-in Helpdesk user may look up an order. (The order-to-customer check needs data the
// gateway doesn't have; the lab's PEP does it locally. On AWS it has to live in the Lambda or in a PEP in front of
// it: see "What this build leaves out" in GUIDED-BUILD.md. This build does not do it.)
permit (
    principal is AgentCore::OAuthUser,
    action == AgentCore::Action::"RefundTools___lookup_order",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when { principal.hasTag("username") };
