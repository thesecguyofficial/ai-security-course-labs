"""
safe_filter.py: build helpdesk-web's GA security filter (lesson 13.1).

Microsoft: "The principal is just a string, used in a filter expression". Whatever string you build IS the
authorisation decision for the GA path. Contoso version 1 glued strings together, so a "department" value such as
  x' or true or title eq 'y
turned "only my groups AND this department" into "everything".

CHALLENGE 3: make build_filter() safe.
  - groups come from the validated token; accept only the group names in data/directory.json, else raise ValueError
  - search.in splits on spaces and commas by default: a group value containing either must be refused
  - department is user input: escape single quotes the OData way (' becomes '') so it stays inside its string
The hardened build ALSO forwards the user's token, so native trimming would catch a widened filter on this index.
Fix it anyway: the GA filter is the only control on indexes without native ACL fields.
"""


def build_filter(groups: list[str], department: str | None) -> str:
    flt = f"group_ids/any(g: search.in(g, '{', '.join(groups)}'))"
    if department:
        flt += f" and title eq '{department}'"
    return flt
