# AGENTS.md

## Commit

- Use English for commit messages
- Keep commit descriptions simple

## Comments

- Use concise comments in code
- Only describe in detail when the logic is complex

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
