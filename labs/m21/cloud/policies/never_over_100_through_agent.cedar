// Guided build. Over $100 is never paid through the agent's gateway, whoever is signed in. The agent files
// request_refund_approval instead; a supervisor pays approved refunds in the back office (human deferral, 21.4).
forbid (
    principal,
    action == AgentCore::Action::"RefundTools___issue_refund",
    resource == AgentCore::Gateway::"GATEWAY_ARN"
)
when { context.input.amount_cents > 10000 };
