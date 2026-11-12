# GC11 console rehearsal notes (13 Nov 2026)

Working notes for the recording script. Console in the owner's account; Cloud Shell only where the console can't.

## Before the takes (owner)
- Console language is English (UK) ("Organisation"): switch to English (US) in console preferences. <!-- style-ok: quotes the UK console -->
- Banner on API pages: "To avoid losing access to Google Cloud services, an administrator must verify this account."
  with a **Verify account** button: owner step.
- Mask in the edit: project number (in `NUMBER-compute@developer...`), OAuth 2 client IDs on the service accounts list.

## 1a Identity
- IAM and admin > Service accounts > **+ Create service account**: page "Create service account", steps
  1 Create service account / 2 Permissions (optional) / 3 Principals with access (optional).
  Fields: **Service account name**, **Service account ID \*** (auto-filled from the name: clear it and type the ID),
  **Service account description**. Button used: **Create and close** (skips steps 2 and 3).
  - `TSG Helpdesk runtime` / `chatbot-runtime`; `Ticket summariser` / `ticket-summariser`. Both show "No keys".
  - Wait for the page to load before typing (the first try typed into an unloaded form).
- Custom role: IAM and admin > **Roles** > tab **Custom** ("Customised roles", UK console). A role deleted by an <!-- style-ok: quotes the UK console -->
  earlier run shows **Status: Deleted** and keeps its ID for 37 days, so **+ Create custom role** with
  `helpdeskModelCaller` would fail. In the rehearsal: tick the row > **Undelete** ("Role 'Helpdesk model caller'
  undeleted", Status Enabled) > **Details** shows "1 assigned permissions: aiplatform.endpoints.predict".
  - The **+ Create custom role** page stayed on a spinner twice (direct URL and from the list). Re-test before the take;
    for a clean take use a project where the role was never created, or show Undelete and say why.
- IAM > **Grant access**: panel "Grant access to tsg-course-lab". **New principals \***: type the first email, then
  `,` and the second (both become chips). **Select a role \***: click the arrow, type `Helpdesk model caller` in
  Search, pick it (shows the role description). **Save** > toast "Policy updated. It may take a few minutes for these
  changes to become active." Both accounts listed with role Helpdesk model caller.
  - Mask: owner email row (Owner) and the project number in the Compute Engine default account.
  - Leftover to clean: a principal `...agents.global.proj-NUMBER/.../attribute.platformContainer/aiplatform/...` with
    "Vertex AI Agent Engine - Agent Default Access" (from GC14). Remove before recording.
- Console quirk: the first click after a page or panel change is often ignored; click again. Direct URL loads can sit on
  a spinner for 10+ s; wait, or navigate inside the console.

## 1b Network
- VPC network > VPC networks > **Create VPC network** ("Create a VPC network"). Name `helpdesk-vpc`; Subnet creation
  mode **Custom** (default); New subnet: Name `helpdesk-eu`, **Region \*** type `europe-west4` > "europe-west4
  (Netherlands)", IP stack IPv4 (single-stack), **IPv4 range \*** `10.10.0.0/24`, Private Google Access **Off**.
- **Firewall rules**: six suggested rules listed (allow-custom, icmp, rdp, ssh, deny-all-ingress, allow-all-egress);
  none ticked, leave them so.
- **TRAP: Advanced threat detection with DNS Armour** looked pre-selected on "Enable for this network" ("Additional costs
  apply"), and the command preview included `gcloud network-security dns-threat-detectors create ...
  --provider="INFOBLOX"`. Pick **Disabled** and check **Equivalent command line** shows exactly two commands
  (`networks create helpdesk-vpc --subnet-mode=custom ...`, `subnets create helpdesk-eu --range=10.10.0.0/24 ...
  --region=europe-west4`). Show that dialog on camera: it's a good habit to teach.
- **Create** > "Successfully created network helpdesk-vpc." Row: 1 subnet, MTU 1460, Custom, 0 firewall rules.
- Browser quirk seen in rehearsal: screenshots lagged the page (radio looked unchanged after it had changed).
  The recording tool must capture the real repaint; check the take.
- **The private door works in the console** (no Cloud Shell needed): Network services > **Private Service Connect** >
  Connected endpoints > **Connect endpoint**. Target **Google APIs**; **Scope \*** **Multi-regional** (choices: Global |
  Multi-regional | Regional); **Multi-region \*** `eu (multiple regions in the European Union)`; **Target service \***
  `Vertex AI (aiplatform.eu.rep.googleapis.com)`. Endpoint details: **Endpoint name \*** `aiplatform-eu`; **Region \***
  `europe-west4 (Netherlands)`; **Network \*** `helpdesk-vpc`; **Subnetwork \*** `helpdesk-eu`; **IP address** >
  **Create IP address** > dialog "Reserve a static internal IP address": Name `aiplatform-eu-ip`, Static IP address
  **Let me choose**, **Custom IP address \*** `10.10.0.10` > **Reserve**. Leave **Enable global access** unticked.
  **Add endpoint** > "Creating aiplatform-eu..." then "Successfully created aiplatform-eu." (about 30 s).
  - The console reserves a named static address (`aiplatform-eu-ip`); the gcloud path doesn't. Teardown deletes it
    (VPC network > IP addresses) after the endpoint.
- Network services > **Cloud DNS** > **Create zone** ("Create a DNS zone", marked Preview). **Zone type**
  **Private** (the form reflows: fields move down); **Zone name \*** `aiplatform-eu-rep`; **DNS name \***
  `aiplatform.eu.rep.googleapis.com`; Options Default (private); **Networks** > **+ Add networks** > Project
  tsg-course-lab, **Networks \*** tick `helpdesk-vpc` > **OK** > **Done**. Equivalent command line matched the guide.
  **Create** > "DNS zone aiplatform-eu-rep has been successfully created." (zone shows SOA and NS).
- In the zone: **Add standard** ("Create a record set"): DNS name left empty (the zone apex), Resource record type
  **A**, TTL **5** minutes, **IPv4 address 1 \*** `10.10.0.10` > **Create** > "Resource record set
  'aiplatform.eu.rep.googleapis.com.' has been successfully created in zone 'aiplatform-eu-rep'" (A 300 10.10.0.10).
- Network security > **Firewall policies** > **Create firewall rule** ("Create a firewall rule"). Two rules:
  1. `deny-all-egress`: Logs Off; **Network \*** `helpdesk-vpc` (default is `default`: change it!); **Priority \***
     `65000`; Direction **Egress**; Action **Deny**; **Targets** `All instances in the network` (default is
     "Specified target tags"); Destination filter **IPv4 ranges**, **Destination IPv4 ranges \*** `0.0.0.0/0` (press
     Tab so it becomes a chip; check it isn't added twice); Protocols and ports **Deny all**.
  2. `allow-aiplatform-eu-egress`: Network `helpdesk-vpc`; Priority `1000`; **Egress**; **Allow**; All instances;
     destination `10.10.0.10/32`; **Specified protocols and ports** > tick **TCP**, Ports `443`.
  Each time **Equivalent command line** matched the guide's gcloud command exactly; show it on camera before **Create**.
  List: `allow-aiplatform-eu-egress Egress Apply to all IP ranges: 10.10.0.10/32 tcp:443 Allow 1000 helpdesk-vpc` and
  `deny-all-egress Egress Apply to all IP ranges: 0.0.0.0/0 All Deny 65000 helpdesk-vpc`.
  - Watch the Destination filter dropdown: one stray click switched it to IPv6 ranges.

## 1c Encryption
- **Leftover from earlier runs:** Security > Key management shows key ring `helpdesk-eu` (europe-west4) with key
  `helpdesk-data` already there (key rings and keys can't be deleted). Its versions 1 to 3 were "Will be destroyed on
  12/12/2026", Status **Not available**. Rehearsal: **Rotate key** > "Rotate" > version 4 "Enabled and primary",
  Status Available; **Edit rotation period** > Rotation period **90 days** > Save ("Rotation summary: every 90 days").
  In a fresh project this part is **Create key ring** `helpdesk-eu` (Region, europe-west4) + **Create key**
  `helpdesk-data` (Software, Symmetric encrypt/decrypt, rotation 90 days): not rehearsed here.
- BigQuery (dismiss the "Welcome to BigQuery" dialog with **Done** and close "what's new"). Explorer > ⋮ next to the
  project > **Create dataset**: **Data set ID \*** `helpdesk_tickets`; **Data location** `europe-west4 (Netherlands)`;
  **Advanced options** > Encryption **Cloud KMS key** > Key management type Cloud KMS > **Select a Cloud KMS key \***
  > "Keys in 'tsg-course-lab'" > `helpdesk-data` > **OK**.
  - The console then says "The bq-NUMBER@bigquery-encryption.iam.gserviceaccount.com service account does not have the
    'cloudkms.cryptoKeyEncrypterDecrypter' role" with a **Grant** button: click it ("Successful"). That replaces the
    guide's `bq show --encryption_service_account` + `kms keys add-iam-policy-binding`: no Cloud Shell needed.
    Mask the project number in that message.
  - **Create data set** > "helpdesk_tickets created." Then `ai_logs` the same way (key remembered, no Grant prompt):
    "ai_logs created."
- Dataset access (replaces the guide's `GRANT` SQL): open the dataset > **Share** > **Manage permissions** ("Share
  permissions for helpdesk_tickets") > **Add principal** > "Grant access to helpdesk_tickets": New principals
  `chatbot-runtime@...`, **Select a role** > search `BigQuery Data Viewer` > pick > **Save** > "Policy updated". Again
  for `ticket-summariser@...` with `BigQuery Data Editor`.
  - Clicking dataset names in the Explorer tree didn't open them in the rehearsal (twice); the URL did. On camera,
    click the dataset name once and wait 3 s.
  - Typing the role name before the role search box has focus puts the text into the principals box: click the role
    dropdown, wait for the Search box, then type.
- Cache (GC11-11 answer): no console page; Cloud Shell `curl ... PATCH .../cacheConfig` (Cloud Shell step on camera).

## 1d Logging
- IAM and admin > **Audit logs**. The service row is still named **Vertex AI API** (not Agent Platform). Filter:
  type `Vertex` + Enter (typing `aiplatform` finds nothing); press Esc to close the suggestions; tick the row; right
  panel "Permission types": tick **Data read** and **Data write** > **Save** > "Changes saved".
- Request-response logging: Cloud Shell, `terraform/scripts/request_response_logging.sh on PROJECT_ID eu` (no console).

## Test VM (console)
- Compute Engine > VM instances > **Create instance**. Machine configuration: Name `helpdesk-vm`, Region
  `europe-west4`, Zone `europe-west4-a`, E2 > `e2-small`.
- OS and storage: default image is **Debian GNU/Linux 13 (trixie)**: fine.
- **Data protection** defaults to a snapshot schedule (`default-schedule-1`): pick **No backups**.
- Networking: nic0 Network `helpdesk-vpc`, Subnetwork `helpdesk-eu`, **External IPv4 address None**.
- Observability: **Install Ops Agent** is ticked by default. Untick it with a real click and check **Equivalent code**:
  while it is on, the code adds `--metadata=enable-osconfig=TRUE`, a `goog-ops-agent-policy` label and a second
  command `gcloud compute instances ops-agents policies create ...`. After the untick, one `instances create` command only.
- Security: Service account `TSG Helpdesk runtime`, Access scopes **Allow full access to all Cloud APIs** (IAM decides);
  Secure Boot on.
- Advanced > Automation > **Startup script** (not the Description box above it: easy to mix up): paste the smoke script.
- **Create** > back on VM instances with `helpdesk-vm` in europe-west4-a. Estimate shown: about US$0.02/hour.
- Debian 13 (the console default) passed the smoke test; the guide's gcloud line says `debian-12`. Either works.

## Test 1 in the console (no Cloud Shell)
- VM details > Logs > **Serial port 1 (console)** ("Loading serial port output can take a few minutes"). About 2 min
  after create, Ctrl+F `TSG-SMOKE` shows the same three lines as the guide (10.10.0.10 / HTTP 200 / 000blocked).

## Step 3 trap in the console (no Cloud Shell)
- VM details > **Edit** > Automation > Startup script: change `aiplatform.eu.rep.googleapis.com` to
  `aiplatform.googleapis.com` (three places) and `locations/eu` to `locations/global` > **Save** (about 20 s, lands on
  the details page).
- VM instances list > row **⋮** > **Reset** > dialog "Reset helpdesk-vm?" > **Reset**. (The ⋮ on the details page
  didn't show the dialog in the rehearsal: use the list.) The **Learn** side panel kept popping open; close it with X.
- Serial port 1 about 1 min later: `resolve: 2a00:1450:4013:c00::5f aiplatform.googleapis.com`,
  `generateContent HTTP 000 (aiplatform.googleapis.com, locations/global)`, `internet test: 000blocked`. Matches the guide.
- Untrap: Edit again, change both back, Save, Reset.

## Cloud Shell
- After a reconnect, Cloud Shell asks **Authorize Cloud Shell**; Authorize opens a Google popup: the owner clicks it.
  Rejecting or closing leaves gcloud with "No credentialed accounts".
