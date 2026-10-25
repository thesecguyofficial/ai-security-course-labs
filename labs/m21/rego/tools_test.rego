# Unit tests for tools.rego: opa test rego/ -v
package tsg.tools_test

import data.tsg.tools

base := {
	"principal": {"type": "TSG::User", "id": "bob", "attrs": {"role": "support"}},
	"action": "issue_refund",
	"resource": {"type": "TSG::Order", "id": "O-1001", "attrs": {"customer": "sam@customer.example", "total_cents": 4500, "refunded_cents": 0}},
	"context": {
		"input": {"order_id": "O-1001", "amount_cents": 4500, "currency": "USD"},
		"ticket": {"id": "T-501", "requester": "sam@customer.example"},
		"window": {"refunds_1h": 0, "denials_10m": 0},
		"approval": {"verified": false},
	},
}

test_small_refund_on_ticket_order_is_permitted if {
	r := tools.result with input as base
	r.permits == {"refund_ticket_order"}
	count(r.forbids) == 0
	count(r.invalid) == 0
}

test_fourth_refund_in_an_hour_is_forbidden if {
	inp := object.union(base, {"context": object.union(base.context, {"window": {"refunds_1h": 3, "denials_10m": 0}})})
	r := tools.result with input as inp
	"max_3_refunds_per_hour" in r.forbids
}

test_extra_argument_is_invalid if {
	inp := object.union(base, {"context": object.union(base.context, {"input": {"order_id": "O-1001", "amount_cents": 4500, "currency": "USD", "amount": "950.00"}})})
	r := tools.result with input as inp
	"argument amount should not exist" in r.invalid
}

test_amount_as_string_is_invalid if {
	inp := object.union(base, {"context": object.union(base.context, {"input": {"order_id": "O-1001", "amount_cents": "4500", "currency": "USD"}})})
	r := tools.result with input as inp
	"argument amount_cents should be of type integer" in r.invalid
}

test_other_customers_order_gets_no_permit if {
	inp := object.union(base, {"resource": {"type": "TSG::Order", "id": "O-2001", "attrs": {"customer": "lee@customer.example", "total_cents": 120000, "refunded_cents": 0}}})
	r := tools.result with input as inp
	count(r.permits) == 0
}
