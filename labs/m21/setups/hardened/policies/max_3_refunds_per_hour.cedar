// At most 3 refunds an hour per signed-in user. refunds_1h = refunds this user was ALLOWED in the last
// 60 minutes, counted by the PEP from its own signed receipts (requests, not completed refunds).
@id("max_3_refunds_per_hour")
forbid (principal, action == TSG::Action::"issue_refund", resource)
when { context.window.refunds_1h >= 3 };
