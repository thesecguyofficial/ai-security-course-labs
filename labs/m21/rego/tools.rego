# The hardened Helpdesk rules in Rego, for Open Policy Agent (OPA 1.x, Rego v1 syntax).
# Same input the PEP builds for Cedar (pep.py, PEP._request): principal, action, resource, context.
# Same semantics as Cedar on purpose: deny by default, any forbid wins, and the result names the rules that decided.
#
# One difference to notice: OPA has no schema step. Cedar refused a missing, extra or wrongly typed argument before
# any policy ran. Here those checks are rules you write yourself (the `invalid` set below), and forgetting one is
# silent. That is the price of a general-purpose policy language.
package tsg.tools

defer_ids := ["refund_over_100_needs_approval"]

max_long := 9223372036854775807

# ------------------------------------------------------------------------------------------- argument shapes
shapes := {
	"lookup_order": {"required": {"order_id": "string"}, "optional": {}},
	"issue_refund": {
		"required": {"order_id": "string", "amount_cents": "integer", "currency": "string"},
		"optional": {"reason": "string"},
	},
	"send_email": {"required": {"to": "string", "subject": "string", "body": "string"}, "optional": {}},
}

args := input.context.input

kind(v) := "integer" if {
	is_number(v)
	v == floor(v)
	v <= max_long
	v >= 0 - max_long
} else := "string" if {
	is_string(v)
} else := "other"

invalid contains msg if {
	not shapes[input.action]
	msg := sprintf("unknown action %v", [input.action])
}

invalid contains msg if {
	some k, t in shapes[input.action].required
	not k in object.keys(args)
	msg := sprintf("missing argument %v", [k])
}

invalid contains msg if {
	some k, v in args
	spec := object.union(shapes[input.action].optional, shapes[input.action].required)
	not spec[k]
	msg := sprintf("argument %v should not exist", [k])
}

invalid contains msg if {
	some k, v in args
	spec := object.union(shapes[input.action].optional, shapes[input.action].required)
	kind(v) != spec[k]
	msg := sprintf("argument %v should be of type %v", [k, spec[k]])
}

# ------------------------------------------------------------------------------------------- permits
role := input.principal.attrs.role

permits contains "lookup_ticket_order" if {
	input.action == "lookup_order"
	role in {"support", "supervisor", "contractor"}
	input.resource.attrs.customer == input.context.ticket.requester
}

permits contains "refund_ticket_order" if {
	input.action == "issue_refund"
	role in {"support", "supervisor"}
	input.resource.attrs.customer == input.context.ticket.requester
}

permits contains "email_ticket_requester_only" if {
	input.action == "send_email"
	role in {"support", "supervisor", "contractor"}
	args.to == input.resource.attrs.requester
}

# ------------------------------------------------------------------------------------------- forbids
forbids contains "refund_amount_sane" if {
	input.action == "issue_refund"
	not amount_sane
}

amount_sane if {
	args.amount_cents > 0
	args.currency == "USD"
	args.amount_cents <= input.resource.attrs.total_cents
}

forbids contains "refund_over_100_needs_approval" if {
	input.action == "issue_refund"
	args.amount_cents > 10000
	not approved_by_another_supervisor
}

approved_by_another_supervisor if {
	input.context.approval.verified == true
	ap := input.context.approval.approver
	ap.id != input.principal.id
	ap.attrs.role == "supervisor"
}

forbids contains "max_3_refunds_per_hour" if {
	input.action == "issue_refund"
	input.context.window.refunds_1h >= 3
}

# ------------------------------------------------------------------------------------------- the answer
result := {"invalid": invalid, "permits": permits, "forbids": forbids}
