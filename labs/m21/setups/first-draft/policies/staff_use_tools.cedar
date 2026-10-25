// FIRST DRAFT. Staff may use the Helpdesk's tools.
// (Reviewer's note: no condition on WHICH order, WHICH customer or WHICH recipient. "Staff" is the whole rule.)
@id("staff_use_tools")
permit (principal, action, resource)
when { ["support", "supervisor", "contractor"].contains(principal.role) };
