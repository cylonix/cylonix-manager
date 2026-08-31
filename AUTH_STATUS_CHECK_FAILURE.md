# BUG: fresh login over an existing node fails — "auth status check failed"

> **RESOLVED 2026-08-12.** Root cause: `state.Disconnect` (stale map-session
> teardown, `state.go:636`) persists a **full-row** NodeStore snapshot via
> `persistNodeToDB` → `Updates()` — node_key included. In the failing run a
> stale session tore down at 07:59:00, exactly during the rotation: its
> pre-rotation snapshot committed after `NodeSetNodeKey`'s targeted update and
> reverted `node_key` to `[892BW]` in the DB while the NodeStore held the new
> `[x/W4u]` (pod log shows "Node disconnected" for 38275 in the rotation
> window). The DB read-by-new-key at auth.go:879 then failed record-not-found;
> DB and store stayed divergent, poisoning retries. The working 07:27 reauth
> simply won the same race (log shows its stale-session teardown landed
> before/idempotently). The 2.2 s refresh = the three writers contending on
> the row lock — same mechanism as REG_TO_RUNNING item C, and the racing
> writer is exactly the stale sessions item B wants to evict.
>
> Fix (headscale submodule, `hscontrol/auth.go`):
> 1. `refreshNodeKeyAndExpiry` updates the **NodeStore before the DB**, so
>    concurrent full-row persists snapshot the new key.
> 2. `checkAuthStatus` reads the node back from the **NodeStore** (source of
>    truth), not the DB; DB read only as fallback. A transiently clobbered
>    row self-heals on the next store-derived persist.
> 3. Visibility (request 1 below): errors now logged at the
>    "auth status check failed" wrap, at the refresh error return (which now
>    logs BEFORE the success line, not after), and at the after-authorization
>    lookup.
>
> No manual DB fixup needed for the wedged phone: after redeploy the store
> reloads from the DB (old key), and the next fresh login rotates cleanly
> under the new ordering.

**Date:** 2026-08-12. **Severity: blocks fresh logins** (logout → login) on the
current deployment; reauth still works. Likely shipped with yesterday's manager
deploy (pod `cylonix` age 23 h at time of diagnosis; both the working reauth
and the failing fresh login below ran on it — the fresh-login-over-existing-node
path had probably not been exercised since the deploy).

## Symptom

Android client (node 38275, machine `[7Gttf]`, user randy.huang@ezblock.io):
after logout → login, the web flow completes normally, then the client receives
a RegisterResponse with `machineAuthorized=false, authURL=false` and error
string **"auth status check failed"**; ipn drops to NeedsLogin ("You are logged
out. The last login error was: auth status check failed"). Every retry fails
the same way (each fresh attempt generates a new node key and hits the same
path). Reauth (existing session, old node key present) works.

## Evidence

Failing fresh login, session `7ZDHTWB2`, 2026-08-12 UTC (manager pod log):

```
07:58:59.073  confirm-session POST 200
07:59:00.314  "User logged in 0196de8f-…"                 (checkAuthStatus)
07:59:00.328  "Node already registered"                    (auth.go:844)
07:59:00.328  info "node key and expiry refresh" node_id=38275 node_key=[892BW] new_node_key=c7f5b8b8…
07:59:00.339  "No wg gateway assigned … skip rotate node key in gateway."
07:59:02.535  "Node registered after logged in."           (auth.go:851 — logs BEFORE the err check)
              — NOTHING AFTER —
07:59:03.03   client receives error "auth status check failed"
```

Compare the WORKING reauth ~30 min earlier (session `SRP45TDO`, same code path):

```
07:27:58.760  "Node registered after logged in."
07:27:58.763  "Node registered after authorization"        (auth.go:881)
```

The failing run never reaches "Node registered after authorization".

## Code path (submodules/headscale/hscontrol/auth.go)

`waitForFollowup` → `checkAuthStatus` → node found by user+machine key →
`refreshNodeKeyAndExpiry(node, newKey, zeroOldKey, &expiry)` (:845) →
`logInfo("Node registered after logged in.")` (:851) →
`h.state.DB().GetNodeByNodeKey(nodeKey)` (:878) → on error
"failed to get node after authorization" → surfaced by `waitForFollowup` as
`NewHTTPError(500, "auth status check failed", err)` (:350).

Two silent-failure candidates after ":851" (nothing else logs on failure):
1. **`GetNodeByNodeKey(newKey)` at :878 returning record-not-found** — i.e.
   the rotation write did not land or is not visible to this read. All failure
   branches inside `refreshNodeKeyAndExpiry` have log lines (rotate-node-key,
   DB node-key write, NodeStore-miss warn, expiry write) and none appear, so
   the refresh itself appears to have succeeded. This is the prime suspect.
2. An error path inside `refreshNodeKeyAndExpiry` that returns without logging
   (double-check the `h.state.UpdateNode` / expiry interplay after the v0.28
   merge).

Also note the refresh step took **2.2 s** (07:59:00.33 → 07:59:02.53) in the
failing run vs ~1.5 s in the working one — see REG_TO_RUNNING_LATENCY.md item
C; whatever is slow in there may also be implicated (lock/timeout on the nodes
row?).

## Requested fixes / next steps

1. **Make the failure visible**: log the wrapped error at both
   `waitForFollowup`'s `NewHTTPError(… "auth status check failed", err)`
   (auth.go:350) and `checkAuthStatus`'s return sites (:853 wraps refresh
   errors, :879 wraps the lookup error). This bug was diagnosable only by the
   ABSENCE of a log line. Also move `logInfo("Node registered after logged
   in.")` after the err check (:851-854) — it currently logs success before
   knowing whether the refresh failed.
2. **Inspect the DB row now**: what `node_key` does the `nodes` row for
   node_id 38275 / machine `[7Gttf]` hold — the old `[892BW]`
   (f3dd815a…) or one of the new keys from the failed attempts (e.g.
   c7f5b8b8…)? Old key ⇒ `NodeSetNodeKey`'s write silently didn't persist
   (check the gorm update in `db.NodeSetNodeKey` against the v0.28 schema —
   e.g. a WHERE clause matching on the in-memory node's stale key, or an
   update against a column that moved in the merge). New key ⇒ the write
   landed and `GetNodeByNodeKey`'s read path is at fault (extra WHERE
   constraints? NodeStore vs DB divergence?).
3. **Regression test**: logout → fresh login on a machine whose node row
   already exists (this exact flow). Reauth alone does not cover it.

## Interim workaround for testing

Deleting the device (node row) for the phone in the admin console should
un-wedge it: the next fresh login then takes the node==nil branch
(`registerNodeForOIDCCallback`, auth.go:868) instead of the failing
rotate-existing-node branch.

## Not related to client changes

The client-side map-backoff reset shipped today never engages in this flow
(it only acts after auth SUCCESS, which is never reached). The RegisterReq
polling cadence seen in the logs is the untouched authRoutine. The same
manager build handled this morning's reauth fine (07:27), so this is
manager-side state/path dependent, not a client regression.
