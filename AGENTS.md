# AGENTS.md

## Commit

- Use English for commit messages
- Keep commit descriptions simple
- Never create PRs proactively; only create one when the user explicitly asks.

## Comments

- Use concise comments in code
- Only describe in detail when the logic is complex

## Edits

- When changes are concentrated in a single small file (≤500 lines) and touch 3+ spots, rewrite the whole file at once instead of applying edit calls one by one.
- Otherwise, prefer targeted edits to avoid touching unrelated parts.

## Design Alignment

- Directional decisions (mechanism choice, added complexity, conflicts with the codebase's established style) must be confirmed with the user before implementing; do not implement first and get overridden later.
- Complexity is a misalignment signal: if a small requirement needs heavyweight machinery (background threads, framework magic, hidden global state) to implement, stop and confirm the design direction with the user instead of working around the technical problems on your own.
- When the user questions the implementation approach, stop and re-align the goal first; do not explain the current approach and continue.
- Prefer the mechanism the codebase already uses (explicit state machines, I/O-free core, testability). If the natural mechanism for the requirement conflicts with that style, ask the user which direction they want before building.

## Doc

- Docs must contain version number and last modified time
- Last modified time aligned to day-level precision (e.g. 2026-08-30)
- No need to list change history; git history covers it

## Doc Workflow (requirements-driven evolution)

Docs are organized as: requirements (why/when) → design (authoritative behavior) → tests (acceptance) → e2e/ci (evidence).

- **Propose a change**: create `docs/requirements/REQ-NNN.md` (status `proposed`, priority `P0/P1/P2` aligned with the roadmap phases, `依赖: <REQ-NNN>` if a predecessor must merge first, includes draft acceptance criteria). Do not modify design/ directly yet.
- **Merge** (after user confirmation): move the behavior content into the design/ section (mark with the REQ), then slim the REQ stub to `动机 + 决策摘要 + 去向: <SHORTNAME> §x.y` and drop the priority/dependency (proposed-only fields). Add a test scenario (`docs/tests/`, status `待补充`) referencing the REQ.
- **Acceptance**: implement the test → confirm CI is green via `gh run watch` → update the scenario status to `已覆盖` and fill the `证据` column. CI green = accepted.
- **Lessons gate**: when merging a behavior into design/, check `docs/lessons/` review triggers (复核触发点) and note related lesson IDs in the REQ stub.
- **Verify**: after any docs change, run `./docs/ci/check-docs.sh`.

### Doc references from code comments

- Use the short-name + section convention: `FRAME_HEADER §2.6` (see the registry in `docs/design/README.md`).
- Only reference docs where the code binds to a protocol/security contract (constants, wire format, crypto semantics). Pure implementation logic gets no reference.
- The short name must be registered; `§x.y` must exist as a numbered heading in the target file (checked by `check-docs.sh`).
- Keep reverse references (design → src paths) sparse; they belong only in "决策记录/实现级决定" sections.

## Protocol Versioning

- The project has never been officially released. As long as crate versions stay below `2.x.x`, protocols (wire format, message families, semantics) may be changed directly without backward compatibility. No `v1`/legacy coexistence or compatibility shims are required.
- Backward compatibility (and mixed-version interop verification) only starts once a crate version enters `2.x.x`; then `1.x.x` wire behavior must be honored.
- In-repo protocol negotiation fields (e.g. `protocol_version`) are still part of the design; do not add extra override hooks or compatibility e2e scenarios just to exercise legacy versions.

## Verify

- After any docs change, run `./docs/ci/check-docs.sh`.
- Local gate before commit: `cargo +stable nextest run`, `cargo +stable clippy --all-targets -- -D warnings`, `cargo fmt --all -- --check`, then `./e2e/run_e2e.sh` (default `direct` scenario) and `MESH_E2E_SCENARIO=relay ./e2e/run_e2e.sh`.
