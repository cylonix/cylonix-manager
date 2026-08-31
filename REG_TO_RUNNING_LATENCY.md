# Registration → Running latency: manager-side work items

> **POST-DEPLOY MEASUREMENT 2026-08-12 (after the rotation-race fix):** reauth
> on the Android phone, all UTC:
> - 08:45:12.392 "Node registered after logged in." AND "…after authorization"
>   — same millisecond: the old 1.5–2.2 s registration transaction is GONE
>   (item C largely resolved by the reordering).
> - 08:45:12.87 client receives success and immediately opens its map poll
>   (single request, no client retries, no backoff involved).
> - **08:45:17.12 "node has connected, mapSession" — 4.2 s AFTER the poll was
>   sent.** Then AddNode 810 ms, client applies netmap at 08:45:19.0.
>
> The remaining bottleneck is therefore BETWEEN the noise poll request
> arriving and `poll.go:584` registering the session — before AddNode, before
> map generation. Same signature seen on a fresh login (3.2 s) and this reauth
> (4.2 s); a plain app-restart session (no key rotation) shows NO such gap
> (accepted immediately, AddNode 191–659 ms). So it is specific to the
> first poll after a key rotation. Suspects: `serveLongPoll`'s pre-session
> steps (`state.UpdateNodeFromMapRequest`, `state.Connect`), a node lookup
> that only succeeds after NodeStore/batcher propagation of the rotated key,
> or serialization against the OLD session's teardown (item B, still open).
> **Request: instrument serveLongPoll with per-phase timestamps from request
> arrival to "node has connected"** — the 4 s is currently invisible, same
> diagnosability gap as the auth bug. Fixing this + item A should reach the
> ~2–3 s target; AddNode at 810 ms for a 3-peer map also suggests worker-pool
> queueing worth a look while in there.

> **UPDATE (after the serveLongPoll/rotation deploy): the rotation path is
> fixed, the NEW-NODE path is not.** Phone reauth 2026-08-12 09:14 UTC:
> registration instant, session accepted **61 ms** after the poll, AddNode
> **87 ms**, auth→netmap 0.68 s — target met for reauth. But a first-ever
> Apple sign-in on macOS (new user + NEW node, id 88, 2026-08-13 02:35 UTC)
> shows the same old signature on the node-creation path:
> - 02:35:08.775 registration complete (instant, both lines same ms)
> - client opens its poll immediately (single streaming request, no retries;
>   a parallel lite endpoint-update took "5.487s" server-side)
> - **02:35:15.046 "node has connected" — 6.2 s pre-session gap**
> - 02:35:16.017 AddNode 968 ms
>
> Whatever visibility/propagation the rotation fix gave the poll's node
> lookup needs the same treatment for a FRESHLY CREATED node (store insert /
> batcher propagation after node+user+IP provisioning). First-login UX (every
> new user's first impression) currently pays ~7 s where reauth pays ~1 s.

**Date:** 2026-08-12. Companion to the client-side fix already made in the
cylonix tailscale fork (map-poll backoff reset on auth success,
`control/controlclient/auto.go`). Measured end-to-end: tapping Connect on the
confirm page → backend Running took **~7.4 s** (up to ~10 s with unlucky poll
timing). Target after all fixes: **~2–3 s**.

## Measured timeline (Android reauth, node 38275, 2026-08-12 ~07:27 UTC)

All timestamps from the manager pod log (grep patterns shown) and the client's
adb log; node key short form `[892BW]`, machine key `[7Gttf]`, login session
`SRP45TDO`.

| UTC | Event | Source |
|---|---|---|
| 07:27:56.577 | confirm-session POST returns 200 | `confirm-session?session_id=SRP45TDO` |
| 07:27:57.20 | next client RegisterReq poll arrives; "Node already registered" | `[7Gttf]` |
| 07:27:57.21 | node-key rotation bookkeeping ("skip rotate node key in gateway") | `[7Gttf]` |
| 07:27:58.76 | "Node registered after logged in." / "…after authorization" | `[7Gttf]` |
| 07:27:59.24 | client receives machineAuthorized=true (adb) | — |
| 07:27:59.26 | client's first post-auth MapRequests arrive (×2) | "using NetInfo from previous Hostinfo" |
| 07:28:01.06 | another MapRequest (client retry after ~1.8 s backoff) | same |
| 07:28:02.78 | streaming map session finally established | `poll.go:584`, "node has connected, mapSession" |
| 07:28:02.94 | AddNode completes, initial map sent (167 ms) | `batcher_lockfree.go:106 total.duration` |
| 07:28:03.78 | client applies netmap; relay reconnects ~04.0 (adb) | — |

Delay decomposition:
1. **0.6–2.0 s** — poll-interval wait: confirm landed at :56.6 but the client's
   next RegisterReq only came at :57.2 (client polls the followup URL every
   1–2 s; nothing holds the request server-side).
2. **1.55 s** — registration transaction (:57.2 → :58.76).
3. **3.5 s** — map-session re-establishment (:59.26 → :02.78): the client's
   first two attempts did not produce a session; retries were spaced by
   client-side backoff (fixed client-side now) — but the first, immediate
   attempt ALSO failed, which is a server-side problem (see item B).
4. 167 ms — initial map generation (fine; readiness-gate instrumentation
   visible and healthy).

Context worth knowing: before this reauth the node held **3 concurrent map
sessions** ("session released, other sessions keep node online,
active_sessions:3", disconnect_epoch churn), and an AddNode for this node at
07:27:52.7 took **2.0 s** (`total.duration:1999.9`) while broadcasting to all
three stale connections.

## Work item A — hold the followup RegisterReq until the session is confirmed

Removes delay №1 (up to ~2 s) and most of the RegisterReq poll chatter (the
client re-sent RegisterReq ~7 times during one browser login).

Upstream headscale already has a followup long-poll mechanism in its
registration path (`hscontrol/auth.go`, the registration-cache /
`waitForFollowup` flow) — a RegisterReq carrying a Followup URL is supposed to
BLOCK until the auth completes or times out. Our register path answers
immediately with the same AuthURL instead (log: repeated "received register
request with no auth, and no existing node" ~1/s, each answered with
authURL=true). Likely because the cylonix login flow (confirm-session in the
manager daemon, `subsys=login-handler`) completes the registration outside
headscale's followup signaling, so the blocked-waiter channel either isn't
waited on or isn't signaled.

Change: when a RegisterReq arrives with a Followup URL for a pending session,
park it on a channel/context keyed by the registration/session ID; have the
confirm-session handler (and the OAuth completion path for flows without the
Connect confirmation) signal that channel when the node becomes authorized.
Timeout ~30 s → respond authURL-again as today (client re-polls, no behavior
regression). The client already tolerates long-held followup requests —
upstream tailscale's `WaitLoginURL` is designed for exactly this.

## Work item B — evict superseded map sessions at node-key rotation

Addresses the failed first post-auth MapRequests (part of delay №3) and the
2.0 s AddNode with 3 stale connections.

Evidence: the node accumulated 3 live sessions; after registration, the
client's immediate MapRequests (:59.26 ×2, :01.06) produced no session until
:02.78. The overlapping-session model (`multiChannelNodeConn`, "other sessions
keep node online") deliberately tolerates old sessions, but a **node-key
rotation is a hard boundary**: sessions opened under the previous node key can
never serve the new identity and only cost work (every broadcast fans out to
every connection; AddNode's initial-map generation is serialized behind the
shared worker pool).

Change: in the registration path, at the point the node key is rotated /
re-registered (log anchor: "refresh_expiry": true, "rotate node key" lines,
07:27:57.21), proactively close all existing map sessions/channels for that
node id (batcher `RemoveNode`/connection close + poll session cancel), so the
next MapRequest starts from a clean slate. Also consider a general cap: when a
NEW streaming session for a node establishes, close any session whose noise
connection or node key generation is older (keep at most the newest 1–2).
Investigate too WHY the :59.26 MapRequests failed to establish a session —
whether they were rejected for key mismatch against a cached node, or aborted
during stale-session teardown; add a log line for map-session rejection reason
(currently the failure is silent server-side, which made this diagnosis
harder than it needed to be).

## Work item C — profile the 1.55 s registration transaction

"Node already registered" (07:27:57.207) → "Node registered after logged in."
(07:27:58.760). For a reauth where nothing material changed, 1.55 s implies
several sequential DB round trips and/or external checks (expiry refresh, user
last-seen update, wg-gateway rotation check, tenant/label lookups). Add spans
or debug timings per step, then batch what can be batched and skip writes when
values are unchanged. Target ≤ 0.5 s. (Fresh registrations additionally do
node creation + IP allocation — worth timing in the same pass.)

## Expected effect

| Fix | Saves |
|---|---|
| Client backoff reset (already done, cylonix tailscale fork) | ~3 s |
| A: followup long-poll | 0.6–2 s |
| B: session eviction at rotation | first MapRequest succeeds; AddNode stays ~150 ms |
| C: registration transaction | ~1 s (to be confirmed by profiling) |

Combined: tap-Connect → Running ≈ 2–3 s (from 7.4–10 s).

## Verification

Repro loop: on the Android test phone, force-stop + relaunch the app, run
logout → login (or reauth from settings), and measure from confirm-session in
the manager log to the client's "derp connected" (adb logcat, tag gojni).
Client-side markers: `RegisterReq: got response; machineAuthorized=true` →
`magicsock: derp-… connected`. Manager-side: confirm-session POST →
"node has connected, mapSession" for the node id. After fix A the RegisterReq
poll chatter during browser auth should collapse to one held request; after
fix B a node should never show active_sessions > 1 right after a rotation.
