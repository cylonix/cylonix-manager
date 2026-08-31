# Empty netmap on new map sessions — root cause and fix plan

**Date:** 2026-08-11. Diagnosed from live client logs (Android capture, Mac
`/var/log/cylonix/cylonixd.log`) plus a code investigation of this repo.

**User-visible impact:** every client of the account (Android, iOS, macOS alike —
no platform difference) intermittently receives a broken netmap that wipes peers,
DNS, and the DERP map for ~150 ms. Due to a client-side recovery bug (being fixed
separately in the `tailscale` submodule, see §5) the relay connection then stays
down until an app restart / tunnel bounce / rebind, showing "relay server
unreachable" (`no-derp-connection` health warnable) indefinitely.

## 1. Observed signature (client side)

Android capture, node 38261, tester@cylonix.io (phone-local time):

```
14:11:23.503  active login: <missing-profile>
14:11:23.581  l2relay: setNetMap ... segmentID="XuYQzqllrq6UwzRf" strong=false
14:11:23.583  magicsock: closing connection to derp-903 (derp-disabled), age 4s
14:11:23.586  wgengine: Reconfig ... (with 0/0 peers)   [DNS wiped too]
14:11:23.617  active login: tester@cylonix.io
14:11:23.675  l2relay: setNetMap ... segmentID="2mVY9sVWo7jXN-og"
14:11:23.684  wgengine: Reconfig ... (with 0/28 peers)  [then 29, 30]
```

The broken netmap simultaneously has: 0 peers; the self user missing from
UserProfiles; **nil DERPMap** (→ `SetDERPMap(nil)` → "derp-disabled"); and a
different l2relay segment ID. Corrected ~150 ms later. Four events on the Mac in
one evening (2026-08-10 21:24–22:28 PDT); correlated with map-poll reconnects.

## 2. Root cause (this repo) — confidence: very high

The broken netmap is a **bare `selfMapResponse` racing ahead of the initial full
map on a brand-new map session**.

Mechanism, with code references:

1. `mapSession.serveLongPoll` (`submodules/headscale/hscontrol/poll.go:137`):
   on a new session, `LockFreeBatcher.AddNode` is called (`poll.go:248`).
2. `AddNode` (`hscontrol/mapper/batcher_lockfree.go:49-108`) **registers the new
   connection channel first** (`:74`, intentional — see comment at
   `poll.go:243-247`), *then* generates the initial full map through the shared
   worker pool (`:77`, blocking, ~100–200 ms — `state.ListPeers` + per-poll
   `NodeHandler.Peers` DB call + policy filters for ~30 peers), and only then
   pushes it into the channel (`:87`).
3. In that window, any already-queued broadcast change for this node is
   delivered into the fresh channel **first**. The main supplier: the *previous*
   reconnect's `UpdateNodeFromMapRequest` returns `change.NodeAdded(id)` with
   `OriginNode = id` whenever hostinfo changed (`hscontrol/state/state.go:2805`,
   also `:2787`, `:2827`; endpoint/DERP variant `:2824`), and those sit in
   `pendingChanges` for up to the **800 ms batch tick**
   (`tuning.batch_change_delay`, `types/config.go:415`) before workers broadcast
   them. Reconnect churn (Wi-Fi↔cellular handoff testing) makes this collision
   routine. gRPC `UpdateNode`/`CreateNode` from the cylonix daemon
   (`grpcv1.go:1768`, `:1695`) emit the same origin-self changes.
4. `generateMapResponse` (`hscontrol/mapper/batcher.go:98,121-123`) converts an
   origin-self non-policy change into **`selfMapResponse`**
   (`hscontrol/mapper/mapper.go:183-201`): `Node` only, `Peers` forced nil, and
   the DERPMap / Domain / UserProfiles builders are never run. (Contrast
   `fullMapResponse`, `mapper.go:160-181`, which always attaches all of them —
   no full-response path can produce this signature.)
5. Client side, tailscale's map session caches DERPMap / Domain / UserProfiles
   per session (`control/controlclient/map.go:116,320,363-379,432-433`). When a
   bare self response is the **first** message of a fresh session, the caches
   are still empty → applied netmap has nil DERPMap, empty Domain, no user
   profiles, no peers. All four symptoms from one response.

The cylonix fork's overlapping-session model (`state.go:547-596`,
`poll.go:149-207`; `multiChannelNodeConn` holding old + new channels) widens the
exposure relative to upstream headscale, but upstream inherited the same
`AddNode` shape.

**The segment ID is a red herring.** There is no server-side segment concept.
l2relay segment IDs are computed client-side
(`cylonix/tailscale/ipn/l2relay/relay.go:596-625`) as
`sha256(nm.Domain + "|segv2|...")` — `XuYQzqllrq6UwzRf` is just the same LAN
hashed with an **empty Domain salt** (Domain missing from the bare response),
which is also why the same "wrong" ID shows up on all devices on that LAN.

## 3. Fix plan (server, this repo)

Preferred, batcher-side — **connection readiness gate**:
- Add a `ready atomic.Bool` (or small pending-updates buffer) to
  `connectionEntry` (`batcher_lockfree.go:492-499`).
- `entry.send` / `mc.send` (`:598-666`, `:669-693`) skips (or queues) entries
  whose initial full map has not yet been enqueued.
- `AddNode` flips ready **after** `c <- initialMap` (`:87`) and flushes anything
  queued. Skipping is safe for changes that landed before full-map generation
  began (the full map already reflects them); buffering closes even the residual
  window.

Alternative, session-side invariant (small and robust): in `serveLongPoll`'s
write loop (`poll.go:274-287`), drop any non-keepalive update until the first
response with `Peers != nil` (the initial full map) has been written on this
session — dropped self/patch responses are strictly superseded by the imminent
full map.

Defense in depth: assert server-side that the first response of a stream always
carries DERPMap + Domain + UserProfiles (e.g. upgrade to `FullSelf` if not).

Secondary flake worth fixing while in here: `WithDomain`'s fallback
(`hscontrol/mapper/builder.go:122-134`; `daemon/vpn/node_handler.go:922-936`) —
a transient `GetUserNetworkDomain` DB error silently downgrades a full response
to the server default domain, which flips the client-side segment hash (segment
churn / l2relay leader flaps) without the other symptoms.

## 4. How to verify

- Repro: force map-poll churn on a test node (toggle Wi-Fi/cellular or kill the
  poll connection repeatedly) while a hostinfo-changing update is in flight; on
  the client watch for `active login: <missing-profile>` +
  `magicsock: closing connection to derp-903 (derp-disabled)` within seconds of
  reconnect. With the fix, neither should ever appear.
- Server-side: log/metric when a response is dropped/queued by the readiness
  gate; count should be nonzero under churn (proving the race existed) with no
  client-visible effect.

## 5. Client-side fixes (cylonix/tailscale submodule — tracked separately)

For completeness; these make clients recover even if a broken map slips through:

1. `wgengine/magicsock/derp.go` `SetDERPMap` nil-branch: zero `c.myDerp` before
   `closeAllDerpLocked("derp-disabled")` so a restored map re-selects home and
   reconnects (the stuck bug: stale `myDerp` made `setNearestDERP` treat the
   re-picked region as "no change" and never reconnect — silent, needs app
   restart / rebind / key-reinit to clear).
2. `setNearestDERP` no-change branch: if `activeDerp[derpNum]` is missing and
   the private key is set, `goDerpConnect(derpNum)` — a self-healing invariant
   (home unchanged must still mean home *connected*), runs each netcheck cycle,
   idempotent.
3. l2relay (`relay.go:619-622`): treat `nm.Domain == ""` as "segment unknown"
   instead of hashing with an empty salt, so residual server glitches cannot
   cause segment churn / leader flaps.
