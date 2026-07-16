# Native OpenClaw approval boundary

RightOut has two operator-selectable modes.

## Bounded autonomous campaign

`rightout_start_campaign` requires native `allow-once` and binds:

- one opaque profile;
- an exact canonical broker set;
- exact effect classes (`discover`, `publisher_discover`, `submit_email`, `submit_form`,
  `poll_verification`, `open_verification`, `direct_recheck`);
- a 1-720 hour expiry; and
- a 1-2,000 broker-effect authorization-unit budget. One unit authorizes one
  broker/effect session; that bounded session may contain multiple browser,
  Brave, mail, or verification protocol interactions and is not a raw HTTP
  request counter.

The approval description shows the opaque subject reference, possible PII field
classes, recipient/embedded-processor classes, selected browser backend, an
exact broker list while it fits the Gateway limit, effect names, lifetime, and
budget. The pinned 22-broker set uses the human-readable `Unbroker pinned 22`
label; all requested effects are always named with readable lifecycle labels.
The binding contains the complete normalized broker/effect scope, catalog
digest, current market-policy digest, and approval-time routing digest rather
than relying on display text. A source-review or regulatory phase transition
changes that digest and invalidates the unused approval.

The grant is encrypted at rest. Each in-scope provider effect revalidates the
profile, broker, effect class, catalog digest, market-policy digest, expiry,
revocation status, and remaining budget before execution, then atomically
consumes budget. It cannot
authorize another profile/broker/effect, widen itself, renew itself, bypass
catalog/consent/transport checks, or survive completion, expiry, or revocation.

Form effects have an additional non-delegable gate: each broker needs a current
written provider authorization bound to the reviewed terms contract digest.
Current public review records 8 explicit prohibitions and 14 `needs_evidence`
routes, so the default autonomous form count is zero. Subject/operator consent
never substitutes for publisher permission.

Every parity provider request also carries exact `execution_jurisdictions`,
`execution_market_ids`, and a closed `provider_request_contract`. Missing,
widened, substituted, review-due, or stale route markets stop before profile
SecretRef use or provider I/O. Subject eligibility is checked separately after
profile resolution and before any provider effect.

`rightout_campaign_next` is replay-safe and returns one deterministic in-scope
command, source/human gate, or `done_for_now` digest. It does not execute network
effects itself.

`rightout_worker_enable` adds a separately approved durable loop around that
planner. The worker is encrypted and bound to one campaign, the exact current
trusted session, runtime/catalog policy, and signed recipe pack. It leases one
fixed-grammar command at a time and accepts completion only after the host
re-binds a terminal result to the exact session, run, call ID, tool, normalized
parameters, lease, and execution digest. Interactive or inconclusive results
become human gates. A scheduler wake is not new authority.
`rightout_worker_resume` needs another approval; revoke is immediate and can
only reduce authority.

## Assisted mode

Without a campaign ID, each provider-I/O tool uses its own `before_tool_call`
request. Decisions are only `allow-once` or `deny`, time out to deny after two
minutes, bind the host tool-call ID and exact normalized scope, and are deleted
on execution. Current OpenClaw rejects unresolved, timed-out, cancelled, denied,
missing-route, malformed, and mismatched approval decisions. RightOut
intentionally omits the deprecated and ignored `timeoutBehavior` compatibility
field.

| Effect | Bound scope | Never authorizes |
| --- | --- | --- |
| Live scan | profile and at most 100 exact brokers, Brave policy/profile digest; long approval labels use a count plus immutable set digest while the binding retains every broker ID | publisher read, mail, form, removal |
| Publisher browser discovery | profile, broker, official main-page origins, current written provider authorization, separate campaign effect | Brave scope, arbitrary top-level navigation, write, identity claim |
| Direct recheck | profile, broker, encrypted listing handle, publisher policy | other URL, redirect, write |
| SMTP removal | profile, broker, market-specific request kind/contract, recipient, SMTP snapshot | retry, another broker, EU/UK contract substitution, completion claim |
| Browser form | profile, broker, catalog route/fields, current written provider authorization | arbitrary browsing, CAPTCHA/ID, a route authorized only by subject consent |
| Inbox poll | profile, broker, read-only mailbox snapshot | link open or write |
| Controller-reply poll | profile, broker, read-only Gmail snapshot, exact outgoing Message-ID thread | automatic controller outcome, write, unrelated message |
| Confirmation open | profile, broker, opaque link handle | another link, mailbox read, removal claim |
| Browser-mail handoff | opaque profile/broker/campaign refs; zero provider I/O | inbox search, message open, link open, campaign budget consumption |

One scan-only campaign scoped to all lanes with an effect budget of at least 56
can drain all 56 code-enforced combined catalog lanes in deterministic
four-broker batches: 30 people-search plus 26 controller/B2B
public-index domains. Three controller portal lanes remain `human_only` and
cannot be promoted by the runtime overlay. Within the pinned Unbroker subset, 21 are
scan-permitted; Spokeo is excluded and remains a durable human gate because its
published terms prohibit automated queries. This does not reduce the 22/22
normalized contract inventory. A controller/B2B domain without a public indexed
person surface remains `inconclusive`, never `not_found`. Country localization
does not establish real-world discovery effectiveness or private-inventory
visibility; both remain `needs_evidence`.
Browser origin checks
pin the top-level page before and after actions. OpenClaw does not expose a
RightOut-specific per-session subresource/XHR egress allowlist, so embedded
provider processors may receive browser requests. Written provider authorization
must cover that processing; this is not network isolation.

## Dedicated human/local approvals

The following never inherit campaign authority:

- subject-state purge;
- encrypted-state key rotation;
- controller-outcome recording;
- ambiguous-write reconciliation;
- evidence export;
- static local dashboard export;
- worker enable and resume;
- California DROP filing attestation;
- California DROP portal-status observation;
- GPC browser-setting/extension observation;
- campaign revocation;
- official parity-source refresh;
- official CPPA registry refresh.

DOB is a separate sensitive-disclosure exception: the campaign may plan the
Intelius form, but `rightout_begin_form_session` cannot expose or fill DOB until
the host receives one exact critical `allow-once` decision for that profile,
broker, campaign, route, and disclosure set. The form then continues
autonomously; the human is not asked to re-enter the data or replace the route.

They record an explicit operator decision or mutate critical local state, but do
not silently contact a provider.

Configuration attestations bind exact profile and transport snapshots, policy
revisions, jurisdiction, and minimum disclosure. Separately, provider permission
records bind a current written-authorization reference to the exact reviewed
terms contract. Neither is legal certification.

Campaign grants created before the market-policy binding existed are not
upgraded or renewed. They fail closed and require a new native approval.

OpenClaw resolves active SecretRefs eagerly at Gateway activation into an
in-memory snapshot. RightOut does not claim otherwise. External subject-PII or
credential use starts only after approval or campaign validation and then
repeats consent, catalog, freshness, permission, domain, transport, and
state-machine checks. Local setup/status/export/doctor operations may read
resolved config or encrypted state without an approval but do not disclose it
or contact a broker with subject data.

`/tools/invoke` is a full-operator surface. Production guidance denies every
manifest tool with `replaySafe: false` unless direct invocation is intended. If
session-bound `teamAccess` is configured, all 50 RightOut tools must be denied
on that surface; any omission is a critical role-bypass audit finding.
OpenClaw plugins are trusted in-process code; approval is not a sandbox against
a malicious plugin or mutually untrusted tenant. Use separate Gateways and OS
identities for that boundary.
