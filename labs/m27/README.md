# Lab M27: review an agent sandbox like an auditor, then prove its egress policy

Companion to lessons **27.1 to 27.4** of *AI Security Engineer* (The Sec Guy). About 30 minutes, **$0**, all on your
laptop: **Python 3.11+ only**, no packages, no network, no model download, no cloud account.

You get the configuration of a code-running analysis agent, the **TSG Data Helper**, in two versions: the first draft
a team shipped, and a hardened one. You review both with a rule checker, then replay **14 pre-recorded connection
requests** from one of the agent's sessions against each policy: 6 normal tool calls and 8 requests the task never
needed. You read the log records each version would leave and run the lesson's alert thresholds over them.

**Nothing in this lab opens a connection, resolves a name or moves data.** A "request" is a line of JSON that says
"the agent asked to reach this name, on this port, this way". The evaluator works out what each control would do,
and the logs are illustrative records in the providers' documented field names. Every destination outside AWS uses a
reserved `.example` or `.invalid` name ([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606)), and a test proves the
lab runs with every socket call blocked.

| Part | What you do | Lesson |
|---|---|---|
| **Review** | 18 rules over the first draft: 16 fail | 27.1, 27.2 |
| **Harden** | The same rules over the hardened config: 0 findings | 27.1, 27.2 |
| **Replay** | 14 recorded requests, layer by layer: 7 of 8 unexpected allowed before, 0 of 8 after, 6 of 6 normal both times | 27.2 |
| **Logs** | What each version leaves in Resolver query logs, flow logs, CloudTrail network activity events, the proxy log | 27.2 |
| **Alerts** | The starting thresholds: pages and tickets | 27.2 |
| **Prove** | `make test` (17 tests) | all |
| **Challenge** | Two missing rules, a burst detector, a shared-session hunt. No solution included | 27.1, 27.2 |
| **Guided build (optional)** | A Code Interpreter in VPC mode with an S3 gateway endpoint and a DNS walled garden in your own AWS account | 27.1, 27.2 |

## Get the lab files

This folder is part of the free, public course labs repository, [thesecguyofficial/ai-security-course-labs](https://github.com/thesecguyofficial/ai-security-course-labs).

**First time, or you deleted the folder:** download it once.

```bash
git clone https://github.com/thesecguyofficial/ai-security-course-labs.git
cd ai-security-course-labs
```

**Already downloaded it:** go to that folder and get the latest version.

```bash
cd ai-security-course-labs
git pull
```

**No git?** On the [labs page](https://github.com/thesecguyofficial/ai-security-course-labs), click **Code → Download ZIP**, unzip it and open a terminal in that folder (download it again to get updates).

Stay in the `ai-security-course-labs` folder: the first step below takes you into `labs/m27`.

## What's in this folder

| File | What it is |
|---|---|
| `configs/first-draft.json` | The agent runtime as first shipped: PUBLIC network, NAT, default endpoint policies, no DNS firewall, a proxy nothing enforces, a wide role, `~/.aws` mounted, two secrets in the environment, 8-hour shared sessions |
| `configs/hardened.json` | The same agent, default-deny outbound: VPC mode, no NAT, endpoint policies, a DNS walled garden that fails closed, one proxy the network enforces, narrow role and mounts, no secrets, 15-minute sessions |
| `configs/second-draft.json` | A later draft for challenge 1. The shipped rules pass it; two gaps remain |
| `data/requests.jsonl` | The 14 recorded requests (N1 to N6 normal, U1 to U8 unexpected). Descriptions only: no bodies, no payloads |
| `data/morning-resolver-log.jsonl`, `data/app-sessions.jsonl` | Recorded logs for challenges 2 and 3 |
| `explore.py` | The read-only helper for Step 1b: one idea at a time (this terminal as a process, a sandbox config, a network config, names against the DNS allow-list, one request layer by layer). It writes no file, starts no program and opens no connection |
| `Makefile` | Short commands for Mac and Linux (`make setup`, `make review` ...); `make -n <target>` shows what one would run |
| `checker.py` | The rule checker. Holds challenge 1 (rules E2 and D3) |
| `egress.py` | The policy evaluator: dns, route, sg, proxy, endpoint and role layers, each with its own verdict |
| `logs.py` | Writes the log records each config would leave, under `state/` |
| `alerts.py` | The lesson's thresholds over those logs. Holds challenges 2 and 3 |
| `run_tests.py`, `test_lab.py`, `test_challenge.py` | The proof and the challenge tests |
| `GUIDED-BUILD.md` | The optional cloud build |

## Needs

- Python **3.11 or newer**: `python3 --version`, or `make setup`. No packages, no internet. There is nothing for `pip`
  to install and no virtual environment to create: the lab uses only Python's standard library. Look before you run:
  `make -n setup review` prints the two commands those targets would run, without running them.
- Optional, for Step 1b's container runs only: Docker, as installed in lesson 0.6.
- Mac or Linux for the `make` shortcuts. Windows: run the `python` command shown under each step.

## Step 1 · Review the first draft

```bash
cd labs/m27
make setup
make review
```

```output
Nothing to install for this lab: Python 3.13 and its standard library are all it needs.
Review of first-draft: 18 rules
  [N1] 27.2  Sandbox network mode is VPC: network.mode is PUBLIC
         fix: Set network.mode to VPC: no public network for model-written code.
  [N2] 27.2  No route to the internet: network.nat_gateway is true: the sandbox has a route out
         fix: Remove the NAT gateway route from the sandbox subnets.
  [N3] 27.2  Security group egress names its destinations: egress tcp/443 to 0.0.0.0/0
         fix: Allow egress only to the endpoints and the proxy; no 0.0.0.0/0.
...
25 findings, 16 of 18 rules failed (D1, D2, E1, F1, F2, L1, N1, N2, N3, P1, P2, P3, R1, S1, T1, T2)
```

Each finding names the lesson and the fix, like an audit note. Read them in two groups. **Network (27.2):** PUBLIC
mode with a NAT route, port 443 and 53 open to anywhere, `full-access` endpoint policies, no DNS firewall and fail
open, a wildcard proxy entry nobody enforces, and no logs. **Boundary (27.1):** `s3:*` on `*`, a mounted `~/.aws`,
secrets in the environment, shared 8-hour sessions, no process limit. `make review` exits non-zero on findings, so
the same checker can gate a pipeline (the Makefile ignores that exit code so the steps carry on).

Windows: `python checker.py first-draft`.

## Step 1b · Look at each isolation and egress idea on its own (about 10 minutes)

New to sandboxes and egress? Do this first. `explore.py` shows, one at a time, the ideas the checker and the evaluator
are built on. It only reads: this machine's own facts from `/proc` and `/sys`, and the lab's JSON files. It writes no
file, starts no program, resolves no name and opens no connection. Windows: `py explore.py ...` (`here` needs Linux).
The output below is from a fresh Ubuntu machine (recording run 41083966534).

**1. A process, on a kernel, in a virtual machine.** A process is one running program; it runs as a user and asks
the kernel for files, memory and the network:

```bash
python3 explore.py here
```

```output
This terminal, read from /proc and /sys (nothing is changed)

A process is one running program. This one is explore.py:
  process ID                 2502             its number on this machine
  runs as user               thesecguy        it can open whatever files this user can
  processes it can see       179              every program running on this machine, not just its own

The kernel is the core of the operating system: every program asks it for files, memory and network.
  kernel                     7.0.0-1017-azure

Limits the kernel enforces on this process (ulimit):
  max processes (this user)  58121            how many programs it may start
  max open files             65536            files and network connections open at once

What this terminal runs on:
  inside a container?        no               process 1 is systemd, a normal machine's first program
  virtual machine?           yes              the CPU reports a hypervisor
  hardware says              Microsoft Corporation Virtual Machine

So this terminal is a process, on a kernel, inside a virtual machine: three layers, each with its own limits.
```

**2. A real container (optional, needs Docker).** A container shares the host's kernel but gets its own view, and
Docker can limit its network, files and processes with one flag each. Mac and Windows: Docker Desktop runs containers
inside a Linux VM (on Windows, WSL 2's), so `uname -r` there shows that VM's kernel. Drop `sudo` if your user is in the
`docker` group.

```bash
uname -r && sudo docker run --rm alpine:3.20 uname -r
sudo docker run --rm alpine:3.20 ps
sudo docker run --rm --network none alpine:3.20 wget -q -T 3 -O- http://example.com
sudo docker run --rm --read-only alpine:3.20 touch /home/note.txt
sudo docker run --rm --pids-limit 4 alpine:3.20 sh -c 'for i in 1 2 3 4 5 6; do sleep 2 & done; wait'
```

```output
7.0.0-1017-azure
7.0.0-1017-azure
PID   USER     TIME  COMMAND
    1 root      0:00 ps
wget: bad address 'example.com'
touch: /home/note.txt: Read-only file system
sh: can't fork: Resource temporarily unavailable
```

Same kernel inside and out; one process visible inside; `--network none` leaves only a loopback, so even the name
lookup fails; `--read-only` blocks the write; `--pids-limit 4` stops the fifth process.

**3. The sandbox lines of a config.** Where the code runs, its process limits, its file system limits and its
secrets, in plain words. Try `python3 explore.py sandbox first-draft` too: every `<-` marks a gap.

```bash
python3 explore.py sandbox
```

```output
The sandbox lines of configs/hardened.json, one by one

Where the code runs:
  runtime.boundary                   microvm          a microVM: its own small virtual machine with its own kernel
  runtime.session.one_per_user_task  true             a fresh sandbox per user and task
  runtime.session.timeout_seconds    900              destroyed after 15 minutes

Process limits (how much it may use):
  runtime.limits.vcpu                1                virtual CPUs
  runtime.limits.memory_mb           2048             MB of memory
  runtime.limits.max_processes       128              programs at once: a runaway loop stops here

File system limits (what it may read and write):
  mount /workspace                   rw               the scratch folder: it may write here
  mount /data/reports                ro               input data: read, never changed

Secrets:
  secrets.env                        (none)           no passwords or keys inside the sandbox

The network lines come next: python3 explore.py network hardened
```

**4. The network lines.** Every door out: the network mode, the NAT gateway (the shared door to the internet), the
security group's egress rules, the private endpoints and their policies, the DNS allow-list, and the proxy:

```bash
python3 explore.py network
```

```output
The network lines of configs/hardened.json, one by one

Is there a way out to the internet?
  network.mode                       VPC              PUBLIC = internet access; VPC = only your own private network
  network.nat_gateway                false            no door to the internet

Firewall rules for traffic leaving the sandbox (security group egress):
  tcp/443 to                         endpoint:s3              one named destination only
  tcp/443 to                         endpoint:bedrock-runtime one named destination only
  tcp/3128 to                        proxy                    one named destination only

Private doors to cloud services (VPC endpoints) and their policies:
  endpoint s3                        custom           s3:GetObject, s3:PutObject, s3:ListBucket on tsg-lab-data, tsg-lab-data/*
  endpoint bedrock-runtime           custom           bedrock:InvokeModel on foundation-model/lab-model-a

The phone book (DNS) and its allow-list:
  dns.firewall                       true             names are checked against an allow-list
  dns.allow                          s3.us-east-1.amazonaws.com
  dns.allow                          bedrock-runtime.us-east-1.amazonaws.com
  dns.allow                          proxy.tsg.example
  dns.default_action                 BLOCK            for every other name
  dns.fail_open                      false            if the check is down, refuse (fail closed)

The proxy, a go-between that fetches web pages for the sandbox:
  proxy.allow                        pypi.tsg.example   methods GET, HEAD
  proxy.enforced_by_network          true             the firewall lets the sandbox reach only the proxy
```

**5. Names against the DNS allow-list.** DNS turns a name into an address. A name the resolver won't answer is a
name the code can't connect to:

```bash
python3 explore.py dns placeholder.example.invalid bedrock-runtime.us-east-1.amazonaws.com
```

```output
DNS turns a name into an address. Before the sandbox can connect, it asks the resolver.
configs/hardened.json: DNS firewall true, default rule BLOCK
  allow-list: s3.us-east-1.amazonaws.com, bedrock-runtime.us-east-1.amazonaws.com, proxy.tsg.example

  placeholder.example.invalid
    BLOCKED: placeholder.example.invalid not on the DNS allow-list: default rule BLOCK (NODATA)
    so the code never learns an address to connect to
  bedrock-runtime.us-east-1.amazonaws.com
    answered: bedrock-runtime.us-east-1.amazonaws.com is on the DNS allow-list
    so the code gets an address and may try to connect

No name was really looked up: this is the config's rule, applied on paper.
```

**6. One request, layer by layer.** Every layer must say ok. U1 is a direct post that ignores the proxy:

```bash
python3 explore.py request U1
python3 explore.py request U1 first-draft | tail -n 5
```

```output
Request U1 from data/requests.jsonl, field by field

  when      2027-03-27T09:02:11Z
  kind      https
  name      placeholder.example.invalid
  port      443
  via       direct
  method    POST
  expect    unexpected
  note      direct connection that ignores the proxy, to a name the task never needed

Against configs/hardened.json, in the order the request meets each layer:
  dns       NO  placeholder.example.invalid not on the DNS allow-list: default rule BLOCK (NODATA)
  route     NO  VPC mode, no NAT gateway: no route to the internet
  sg        NO  no egress rule for tcp/443 to internet: REJECT

Every layer must say ok: DENY (dns, route, sg)
  dns       ok  no DNS firewall: the resolver answers for any name
  route     ok  PUBLIC network mode: internet reachable
  sg        ok  egress rule tcp/443 to 0.0.0.0/0

Every layer must say ok: ALLOW
```

The same request: denied three times over by the hardened config, allowed by the first draft.

**7. The proxy checks the method too.** U8 is an upload to the package mirror, which only needs reads:

```bash
python3 explore.py request U8
```

```output
...
Against configs/hardened.json, in the order the request meets each layer:
  dns       ok  proxy.tsg.example is on the DNS allow-list
  sg        ok  egress rule tcp/3128 to proxy
  proxy     NO  POST not allowed for pypi.tsg.example (allowed: GET, HEAD)

Every layer must say ok: DENY (proxy)
```

**8. Read one replay.** `python3 egress.py hardened` prints one line per request: the ID, the verdict, what it asked
for, then each layer in order. Under a denied request: the first layer that said no, and why.

```bash
python3 egress.py hardened | sed -n '1,10p'
```

```output
Replay of 14 recorded requests against hardened
  N1  ALLOW s3:GetObject tsg-lab-data/reports/q3.csv                   dns:ok sg:ok endpoint:ok role:ok
  N2  ALLOW s3:PutObject tsg-lab-data/out/q3-summary.csv               dns:ok sg:ok endpoint:ok role:ok
  N3  ALLOW bedrock:InvokeModel foundation-model/lab-model-a           dns:ok sg:ok endpoint:ok role:ok
  N4  ALLOW GET pypi.tsg.example:443 via proxy                         dns:ok sg:ok proxy:ok
  N5  ALLOW s3:ListBucket tsg-lab-data                                 dns:ok sg:ok endpoint:ok role:ok
  N6  ALLOW DNS bedrock-runtime.us-east-1.amazonaws.com                dns:ok
  U1  DENY  POST placeholder.example.invalid:443 via direct            dns:NO route:NO sg:NO
        first denied by dns: placeholder.example.invalid not on the DNS allow-list: default rule BLOCK (NODATA)
  U2  DENY  DNS placeholder.example.invalid                            dns:NO
```

## Step 2 · The hardened config

```bash
make hardened
```

```output
Review of hardened: 18 rules
0 findings, 0 of 18 rules failed
```

Diff the two configs side by side (`diff configs/first-draft.json configs/hardened.json`). Every changed line maps to
a rule above.

## Step 3 · Replay the recorded requests

```bash
make replay
```

```output
  id  request                                                    first-draft  hardened (denied by)
  N1  s3:GetObject tsg-lab-data/reports/q3.csv                   ALLOW        ALLOW
  N2  s3:PutObject tsg-lab-data/out/q3-summary.csv               ALLOW        ALLOW
  N3  bedrock:InvokeModel foundation-model/lab-model-a           ALLOW        ALLOW
  N4  GET pypi.tsg.example:443 via proxy                         ALLOW        ALLOW
  N5  s3:ListBucket tsg-lab-data                                 ALLOW        ALLOW
  N6  DNS bedrock-runtime.us-east-1.amazonaws.com                ALLOW        ALLOW
  U1  POST placeholder.example.invalid:443 via direct            ALLOW        DENY (dns, route, sg)
  U2  DNS placeholder.example.invalid                            ALLOW        DENY (dns)
  U3  s3:PutObject someone-elses-bucket/drop/file.csv            ALLOW        DENY (endpoint, role)
  U4  PUT someone-elses-bucket.s3.amazonaws.com:443 via proxy    ALLOW        DENY (proxy)
  U5  bedrock:InvokeModel foundation-model/lab-model-z           ALLOW        DENY (endpoint, role)
  U6  GET api.tsg.example:8443 via direct                        DENY (sg)    DENY (dns, route, sg)
  U7  DNS placeholder.example.invalid (firewall down)            ALLOW        DENY (dns)
  U8  POST pypi.tsg.example:443 via proxy                        ALLOW        DENY (proxy)
first-draft: unexpected requests allowed 7 of 8 (U1, U2, U3, U4, U5, U7, U8) | normal tool calls working 6 of 6
hardened   : unexpected requests allowed 0 of 8 (none) | normal tool calls working 6 of 6
```

Read three rows closely.

- **U1** (a direct connection that ignores the proxy) gets out of the first draft because the security group allows
  443 to `0.0.0.0/0`: the proxy was a setting, not a control. The hardened config denies it three times over: DNS has
  no answer, there is no route, and the security group has no rule.
- **U3** (a write to a bucket this agent doesn't own) travels the *private* endpoint in both versions. The first
  draft's endpoint policy is `full-access`, so the private path goes anywhere in S3. Hardened: the endpoint policy
  and the role both say no.
- **U6** is the one request the first draft stops, at the security group (port 8443). Good, but look at Step 4: with
  flow logs off, nobody would ever see it.

Run one config on its own for the reasons: `python3 egress.py hardened`.

## Step 4 · The logs each version leaves

```bash
make logs
```

```output
Logs for first-draft (illustrative values, documented field names) in state/first-draft/
  resolver-query-log.jsonl    0 records
  flow-log.txt                0 records
  cloudtrail-network.jsonl    0 records
  proxy-log.jsonl             3 records
Logs for hardened (illustrative values, documented field names) in state/hardened/
  resolver-query-log.jsonl   14 records
  flow-log.txt                9 records
  cloudtrail-network.jsonl    2 records
  proxy-log.jsonl             3 records
    dns    2027-03-27T09:02:11Z placeholder.example.invalid.     rcode=NOERROR  firewall_rule_action=BLOCK
    dns    2027-03-27T09:02:12Z placeholder.example.invalid.     rcode=NOERROR  firewall_rule_action=BLOCK
    dns    2027-03-27T09:03:15Z api.tsg.example.                 rcode=NOERROR  firewall_rule_action=BLOCK
    dns    2027-03-27T09:03:40Z placeholder.example.invalid.     rcode=SERVFAIL firewall_rule_action=-
    trail  2027-03-27T09:02:30Z s3.amazonaws.com PutObject errorCode=VpceAccessDenied vpcEndpointId=vpce-0lab00000000000s3
    trail  2027-03-27T09:03:01Z bedrock.amazonaws.com InvokeModel errorCode=VpceAccessDenied vpcEndpointId=vpce-0lab0000000000bdr
    proxy  2027-03-27T09:02:44Z PUT someone-elses-bucket.s3.amazonaws.com deny
    proxy  2027-03-27T09:03:58Z POST pypi.tsg.example deny
```

The first draft let 7 unexpected requests through and left **no** DNS, flow or CloudTrail record of any of them. The
hardened config logs every door, and the records use the documented fields: `firewall_rule_action` (set only when a
block or alert rule matched), `rcode` (`SERVFAIL` when the firewall can't answer and fails closed), `errorCode`
`VpceAccessDenied` with `vpcEndpointId`. Open `state/hardened/flow-log.txt`: there is no `REJECT` line, because a name
the resolver refused never became a connection. That is why the DNS log matters most here.

## Step 5 · Alert on them

```bash
make alerts
```

```output
Alerts on the logs of first-draft:
0 pages, 0 tickets
Alerts on the logs of hardened:
  PAGE    vpce-denied        2027-03-27T09:02:30Z s3.amazonaws.com PutObject via vpce-0lab00000000000s3
  PAGE    vpce-denied        2027-03-27T09:03:01Z bedrock.amazonaws.com InvokeModel via vpce-0lab0000000000bdr
  TICKET  dns-block          2027-03-27T09:02:11Z 10.0.1.25 placeholder.example.invalid.
  TICKET  dns-block          2027-03-27T09:02:12Z 10.0.1.25 placeholder.example.invalid.
  TICKET  dns-block          2027-03-27T09:03:15Z 10.0.1.25 api.tsg.example.
  TICKET  dns-servfail       2027-03-27T09:03:40Z placeholder.example.invalid.: firewall did not answer, failed closed
  TICKET  proxy-deny         2027-03-27T09:02:44Z PUT someone-elses-bucket.s3.amazonaws.com
  TICKET  proxy-deny         2027-03-27T09:03:58Z POST pypi.tsg.example
2 pages, 6 tickets
```

The thresholds are lesson 27.2's starting points: any `VpceAccessDenied` from the agent pages, each block or deny is a
ticket. Tune them on a week of data before you trust them.

## Step 6 · Prove it

```bash
make test
```

```output
[PASS] alerts: hardened replay gives 2 pages (VpceAccessDenied) and 6 tickets; the first draft gives none
[PASS] logs: a blocked lookup has firewall_rule_action BLOCK and the documented Resolver query log fields
[PASS] logs: endpoint policy denials are NetworkActivity events with errorCode VpceAccessDenied and the fixed errorMessage
[PASS] first draft: with its logs off, 7 allowed unexpected requests leave no DNS, flow or CloudTrail record
...
[PASS] offline: the checker, the replay, the logs and the alerts run with every socket call blocked
[PASS] offline: every recorded destination outside AWS uses a reserved .example or .invalid name

ALL TESTS PASSED (17 run)
```

## Step 7 · Challenge (no solution included)

```bash
make challenge
```

You should see:

```text
3 of 21 TESTS FAILED (21 run)
```

They fail until you finish.

```output
[FAIL] challenge 1: the checker finds exactly E2 (s3 endpoint resources '*') and D3 (default ALERT) in the second draft
[FAIL] challenge 2: burst_of_blocked_names() pages on 10.0.1.25 only (6 distinct names from 09:10:00Z)
[FAIL] challenge 3: shared_sessions() finds cis-0003, used by alice and chen
...
3 of 21 TESTS FAILED (21 run)
```

1. **27.2: rules E2 and D3 in `checker.py`.** `configs/second-draft.json` fixed every first-draft finding and the
   shipped checker says 0 findings. It still has a custom S3 endpoint policy with `"resources": ["*"]`, and a DNS
   walled garden whose default rule is still `ALERT`. Write the two rules (the docstrings give the contract).
2. **27.2: `burst_of_blocked_names()` in `alerts.py`.** Page when one source address has 5 or more *distinct*
   blocked names inside 10 minutes. The recorded morning has three sources; only one should page.
3. **27.1: `shared_sessions()` in `alerts.py`.** Find Code Interpreter session IDs used by more than one signed-in
   user in `data/app-sessions.jsonl`.

When you finish, `make challenge` ends with `ALL TESTS PASSED (21 run)`, and `python3 alerts.py --morning` shows the
burst page and the shared session.

## Map it to your own stack

The config fields are the questions to ask of any agent runtime: AgentCore's `networkMode` (`PUBLIC`, `SANDBOX`,
`VPC`), your subnets' route tables, each VPC endpoint's policy, the Resolver DNS Firewall rule group and its fail mode,
the proxy and whether the security group forces it, the execution role, mounts, environment and session lifetime.
Write your real config in this shape, run `checker.py` on it, and keep `make test` plus your own recorded requests in
CI so a change that opens a door fails the build.

## How faithful is the model?

| Part | Follows | Note |
|---|---|---|
| Resolver query log fields, `firewall_rule_action` only on alert or block matches | AWS, Resolver query logs format | Values illustrative (placeholder account, IDs and addresses) |
| Flow log line, default version 2 field order, `ACCEPT`/`REJECT`; no records for DNS to the Amazon DNS server | AWS, flow log records and limitations | Values illustrative |
| CloudTrail `NetworkActivity`, `VpceAccessDenied`, the fixed `errorMessage`, `vpcEndpointId` | AWS, CloudTrail record contents | Values illustrative; AWS's page doesn't say whether gateway endpoints produce these events |
| DNS Firewall walled garden, fail closed by default, NODATA block response | AWS, DNS Firewall docs | The evaluator simplifies rule priorities to "allow list first, then the default rule" |
| Layer order and "every layer must allow" | Lesson 27.2 | A model: real networks have more layers (NACLs, route tables per subnet, firewall rule order) |
| Proxy log | This lab's own format | Real proxies (Squid, Network Firewall, Azure Firewall, Secure Web Proxy) each log differently |

## Troubleshooting

- **`make challenge` exits with an error.** Expected until you finish; the last line counts the failing tests.
- **`make review` prints `Error 1 (ignored)`.** Expected: the checker exits 1 when it finds something.
- **Windows:** `python checker.py first-draft`, `python egress.py compare`, `python logs.py hardened`,
  `python alerts.py hardened`, `python run_tests.py`.
- **`make clean`** deletes `state/` and caches.
