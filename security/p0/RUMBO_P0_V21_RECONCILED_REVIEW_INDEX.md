# RUMBO P0 V21 — Reconciled Review Index

Baseline: openai/codex main 7498521d288b9b3b96ffba4eedf089d8d6e06a84

## Cumulative safety reference

The currently reconciled chain is:

V4 -> V5 -> V7 -> V8 -> V9 -> V10 -> V11 -> V12 -> V13 -> V14-FS -> V16 -> V17 -> V19 -> V20

Supersession:
- V16 supersedes V15 approval/provenance semantics.
- V17 supersedes the V14 direct-apply mutation boundary.
- V18 is a reconciliation artifact for V16+V17; it does not add an independent runtime layer.
- V20 restores V13/V14-FS into the effective filesystem chain after they were omitted from an earlier cumulative declaration.

## Current verified evidence

- V20 cumulative structural audit: 40/40 PASS
- V20 cumulative behavioral reference audit: 13/13 PASS
- V20 reconstructed-context git apply/apply --check: 10/10 PASS
- Rust compilation: NOT YET RUN on the cumulative stack
- rustfmt/native cross-platform integration: NOT YET RUN
- Upstream write permission: pull-only
- No change has been merged into openai/codex

## Public provenance / attribution

The public Codex File Operations Safety Protocol in issue #42115 predates the V-series and documents overlapping control ideas such as inventory/manifests, explicit approval, canonical scope validation, fail-closed execution, drift detection, and recoverability.

That public material was consulted as a public engineering reference during reconciliation. The V-series was generated and audited in an AI-assisted session against public upstream source and public issue material. No private prompt package, private architecture, or unpublished implementation material from #42115 was accessed.

Because the public requirements overlap materially, future technical records should attribute the overlapping public requirements to #42115 while keeping any independent implementation claims separate.

## V21 current-main implementation

V21 now contains an actual current-main source delta in the review branch, not only an artifact patch. It hardens `apply_patch` so AddFile/overwrite, DeleteFile, and Update+Move are classified as destructive; destructive patches require fresh user approval, cannot use cached/session approval, cannot be satisfied by permission preapproval or hooks/automatic review, require an enforced sandbox, and cannot retry unsandboxed after sandbox denial. The standalone arg0 apply_patch path rejects destructive patches because it has no approval UI.

This V21 source delta is intentionally narrower than the full V4-V20 proposed safety chain: it is directly reviewable against upstream main, while earlier V-series artifacts remain historical proposal layers until independently merged/validated.

## Review package

The detailed patch files, reports, harnesses, ledgers, and bundles are preserved in the associated local evidence store under /mnt/data/openai_p0_remediation_v3/.

The repository branch containing this index is:
p0/v21-reconciled-review

The branch is based directly on the upstream main commit above and does not modify upstream.

## Remaining material validation gaps

1. Native compilation of the cumulative source stack.
2. Native regression tests on Linux, macOS, and Windows.
3. Kernel/object-identity TOCTOU hardening beyond pre-execution revalidation.
4. Complete mutation-API and direct-spawn coverage.
5. User-visible destructive manifest confirmation.
6. Universal reversible quarantine/recovery and separate permanent purge authorization.

Status discipline: a static PASS is not treated as native compilation/integration evidence.


Revalidation marker: 2026-09-18T07:14:08.157Z — branch integrity rechecked against upstream main 7498521d288b9b3b96ffba4eedf089d8d6e06a84; no production/upstream branch mutation.