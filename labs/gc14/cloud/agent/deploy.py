"""
deploy.py: deploy the GC14 Helpdesk agent to Agent Runtime with its own Agent Identity, bound to your egress
Agent Gateway (GUIDED-BUILD.md, Step 3). Run it from labs/gc14/cloud/agent with your virtual environment active.

    python3 deploy.py --project PROJECT_ID --region us-central1 \
        --gateway projects/PROJECT_ID/locations/us-central1/agentGateways/tsg-gc14-egress \
        --staging-bucket gs://PROJECT_ID-tsg-gc14-staging

Config keys follow Google's pages: identity_type AGENT_IDENTITY (Agent Identity page, ADK quickstart) and
agent_gateway_config.agent_to_anywhere_config.agent_gateway ("Route Agent Runtime traffic through Agent Gateway").
Google's gateway example also sets GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES to False; this script
does NOT (the Agent Identity page calls that opt-out "strongly discouraged"). If your deployment can't call Google
APIs without it, write down why before you add it (lab rule GC14-02).
"""

import argparse
import json

import vertexai
from vertexai import agent_engines, types

from helpdesk.agent import root_agent


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True)
    ap.add_argument("--region", default="us-central1")
    ap.add_argument("--gateway", required=True, help="projects/P/locations/R/agentGateways/NAME (same region)")
    ap.add_argument("--staging-bucket", required=True, help="gs://... (Terraform output staging_bucket)")
    a = ap.parse_args()

    # Agent Identity is set through the v1beta1 API (Google's Agent Identity page uses api_version v1beta1)
    client = vertexai.Client(project=a.project, location=a.region, http_options=dict(api_version="v1beta1"))
    app = agent_engines.AdkApp(agent=root_agent)
    remote = client.agent_engines.create(agent=app, config={
        "display_name": "tsg-gc14-helpdesk",
        "staging_bucket": a.staging_bucket,
        "requirements": ["google-adk[gcp]==2.12.0", "google-cloud-aiplatform[agent_engines,adk]>=1.112"],
        "extra_packages": ["helpdesk"],
        "env_vars": {"TSG_PROJECT": a.project},
        "identity_type": types.IdentityType.AGENT_IDENTITY,
        "agent_gateway_config": {"agent_to_anywhere_config": {"agent_gateway": a.gateway}},
    })
    res = remote.api_resource
    spec = getattr(res, "spec", None)
    print(json.dumps({"name": res.name,
                      "effectiveIdentity": getattr(spec, "effective_identity", None),
                      "identityType": str(getattr(spec, "identity_type", ""))}, indent=2))
    print("\nNext: put effectiveIdentity into cloud/terraform/terraform.tfvars as agent_principal (Step 4).")


if __name__ == "__main__":
    main()
