# Agent-Team Workflow

## Roles

The team uses at most four concurrent roles:

- Coordinator/architect: owns scope, contracts, task boundaries, integration, and phase acceptance.
- Backend/collector agent: owns FastAPI, connectors, collection, normalization, policies, and notifications.
- Frontend agent: owns React UX and generated API integration.
- QA/review agent: writes acceptance tests, independently reviews changes, and runs release verification.

Roles may rotate between waves, but a feature author cannot be its only reviewer.

## Phase Loop

1. Update phase status, requirements, contracts, and acceptance criteria.
2. Freeze module ownership and file boundaries for the wave.
3. Implement in separate branches/worktrees when available.
4. Run author tests and provide a structured handoff.
5. Perform non-author review focused on correctness, security, compatibility, and missing tests.
6. Return blocking findings to the author for correction.
7. QA independently reruns contract, integration, E2E, and Docker checks.
8. Coordinator reconciles the traceability matrix and updates phase documentation.
9. Merge or release only after the phase gate passes.

## Required Handoff

Every task handoff includes:

- requirement IDs and scope
- dependencies and assumptions
- files changed
- commands/tests run and results
- API/schema/documentation changes
- known risks and deferred work

## Shared Workspace Rules

- Assign module/file ownership before parallel work.
- Do not have two agents edit the same contract or migration concurrently.
- Contract changes are coordinator-owned and communicated before dependent work continues.
- Reviewers do not hide blocking issues by making broad unreviewed fixes themselves.
- Generated files are updated through documented commands and checked for drift in CI.

## Documentation Gate

Every pull request states whether it changes scope, capabilities, API, schema, alert semantics, deployment, or operations. A capability fixture and matrix update must be committed with the behavior change. Undocumented behavior does not pass review.

Each phase owns `docs/progress/phase-N.md` with fixed sections for planned requirements, actual changes, deviations, review findings, test evidence, and residual risks. The coordinator updates it at the beginning and end of every implementation wave; a phase cannot close with undocumented deviations.
