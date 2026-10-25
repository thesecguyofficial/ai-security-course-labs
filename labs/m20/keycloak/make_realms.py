"""
make_realms.py: write the two Keycloak realms (tsg-first-draft, tsg-hardened) from the same setups the lab's own
authorization server reads, so both identity providers enforce the same policy.

    python3 keycloak/make_realms.py        # rewrites keycloak/import/*.json

Mapping from setups/<setup>/authz.json to Keycloak 26:
  - each agent client          -> confidential client, "Standard token exchange" switched on
                                  (attribute standard.token.exchange.enabled), its own access token lifespan
  - client "scopes"            -> optional client scopes on that client
  - first draft "audience"/"targets" -> audience mappers on the client (Keycloak adds them to every token it issues)
  - hardened aud:<name> scopes -> client scopes that carry one audience mapper each, so the downscope enforcer can
                                  only ever shrink the audience as well as the scopes
  - downscope_only             -> client policy "any-client" + executor downscope-assertion-grant-enforcer
  - client_credentials         -> service account enabled
Not mapped: record_actor / max_actors. Keycloak's delegation (actor_token, act claim) is a Preview feature; the
exchanged token names the agent that asked for it in `azp` instead. See README, part B.
"""

import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
LAB = HERE.parent
USERS = json.loads((LAB / "data" / "users.json").read_text())
APIS = ["tickets-api", "mail-api"]


def audience_mapper(target: str) -> dict:
    return {"name": "audience " + target, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": target, "access.token.claim": "true",
                       "id.token.claim": "false", "introspection.token.claim": "true"}}


def plain_scope(name: str, mappers=None) -> dict:
    return {"name": name, "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
            "protocolMappers": mappers or []}


def base_scopes() -> list[dict]:
    """We define the realm's client scopes ourselves, so we also define the two built-ins we need."""
    claim = lambda n, attr, claim_name: {  # noqa: E731
        "name": n, "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-property-mapper",
        "config": {"user.attribute": attr, "claim.name": claim_name, "jsonType.label": "String",
                   "access.token.claim": "true", "id.token.claim": "true", "introspection.token.claim": "true"}}
    basic = plain_scope("basic", [{"name": "sub", "protocol": "openid-connect", "protocolMapper": "oidc-sub-mapper",
                                   "config": {"access.token.claim": "true", "introspection.token.claim": "true"}}])
    basic["attributes"]["include.in.token.scope"] = "false"
    profile = plain_scope("profile", [claim("username", "username", "preferred_username"),
                                      claim("email", "email", "email")])
    return [basic, profile]


def realm(setup: str) -> dict:
    policy = json.loads((LAB / "setups" / setup / "authz.json").read_text())
    every_scope = sorted({s for c in policy["clients"].values() for s in c.get("scopes", [])} - {"openid"})
    scopes = base_scopes()
    for name in every_scope:
        if name == "profile":
            continue
        mappers = [audience_mapper(name[4:])] if name.startswith("aud:") else []
        scopes.append(plain_scope(name, mappers))
    clients = []
    for cid, c in policy["clients"].items():
        optional = [s for s in c.get("scopes", []) if s not in ("openid", "profile")]
        rep = {"clientId": cid, "enabled": True, "fullScopeAllowed": False, "directAccessGrantsEnabled": False,
               "defaultClientScopes": ["basic", "profile"], "optionalClientScopes": optional,
               "protocolMappers": [audience_mapper(a) for a in
                                   dict.fromkeys(c.get("audience", []) + c.get("targets", []) + c.get("service_audience", []))],
               "attributes": {"access.token.lifespan": str(c.get("lifetime", policy["default_lifetime"]))}}
        if c.get("public"):
            rep.update(publicClient=True, standardFlowEnabled=True, redirectUris=c["redirect_uris"])
            rep["attributes"]["pkce.code.challenge.method"] = "S256"
        else:
            rep.update(publicClient=False, secret=c["secret"], standardFlowEnabled=False,
                       serviceAccountsEnabled=bool(c.get("client_credentials")))
            if c.get("exchange"):
                rep["attributes"]["standard.token.exchange.enabled"] = "true"
            if c.get("client_credentials"):
                rep["defaultClientScopes"] += c.get("service_scopes", [])
                rep["optionalClientScopes"] = [s for s in optional if s not in c.get("service_scopes", [])]
        clients.append(rep)
    for api in APIS:   # the APIs exist as clients only so audience mappers can name them
        clients.append({"clientId": api, "enabled": True, "publicClient": False, "bearerOnly": False,
                        "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                        "secret": api + "-not-used"})
    out = {"realm": "tsg-" + setup, "enabled": True,
           "accessTokenLifespan": policy["clients"]["helpdesk-app"].get("lifetime", policy["default_lifetime"]),
           "users": [{"username": u["username"], "enabled": True, "email": u["email"], "emailVerified": True,
                      "firstName": u["username"].title(), "lastName": "Lab",
                      "credentials": [{"type": "password", "value": u["password"], "temporary": False}]}
                     for u in USERS.values()],
           "clientScopes": scopes, "clients": clients}
    if policy.get("downscope_only"):
        out["clientProfiles"] = {"profiles": [{"name": "downscope-only", "description": "exchange may only shrink",
                                               "executors": [{"executor": "downscope-assertion-grant-enforcer",
                                                              "configuration": {}}]}]}
        out["clientPolicies"] = {"policies": [{"name": "every-client-downscopes", "description": "", "enabled": True,
                                               "conditions": [{"condition": "any-client", "configuration": {}}],
                                               "profiles": ["downscope-only"]}]}
    return out


if __name__ == "__main__":
    (HERE / "import").mkdir(exist_ok=True)
    for setup in ("first-draft", "hardened"):
        path = HERE / "import" / f"tsg-{setup}.json"
        path.write_text(json.dumps(realm(setup), indent=2) + "\n")
        print(f"wrote {path.relative_to(LAB)}")
