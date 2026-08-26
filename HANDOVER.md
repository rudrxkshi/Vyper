# VYPER handover — tenant isolation slice

## Date and checkout

- Date: 2026-08-26 (Asia/Kolkata)
- Checkout: `C:\Users\Kalpit\Documents\ChatGPT\AGRILEDGER\.tmp\Vyper`
- Branch: `main`, tracking `origin/main`
- Starting commit: `5edf972` (`handover`)

The parent `AGRILEDGER` checkout is unrelated and intentionally untouched.
All work below is uncommitted. Preserve it.

## Work completed in this slice

Implemented the first enforceable central-API tenant-isolation boundary:

- Added explicit `organization_memberships` records, unique on organization and
  user, with `OWNER` or `MEMBER` membership roles.
- A real authenticated creator is made the `OWNER` when creating an
  organization.
- Added scoped organization/member endpoints:
  - `GET /organizations`
  - `POST /organizations/{organization_id}/members`
  - `GET /organizations/{organization_id}/members`
  - `DELETE /organizations/{organization_id}/members/{user_id}` (retains at
    least one owner)
- Added membership checks for organization policies and organization-bound
  enrollment-token creation.
- Policy listing now returns `404` for an unknown organization instead of
  silently returning an empty list.
- Added `PATCH /organizations/{organization_id}/members/{user_id}` and
  `DELETE /organizations/{organization_id}/members/{user_id}`. Only global
  administrators or organization owners can change membership, and the final
  owner cannot be demoted or removed.
- Added remote-policy lifecycle fields (`version`, `revoked_at`) and
  `PATCH /organizations/{organization_id}/policies/{policy_id}`. Policy
  changes increment the version; revoked policies are rejected for new central
  jobs. Unknown policy organizations return `404`.
- Membership writes require global administration or organization ownership;
  the stored owner/member role is now enforced for membership administration.
- Scoped operator access to agents, agent assets, central job creation,
  central-job approval, and central-job/agent list endpoints.
- `SUPER_ADMIN` retains explicit global access. Development compatibility
  identities also retain global access for the pre-existing local test mode.
  All non-super-admin real users fail closed for resources without an assigned
  organization, including legacy null-organization agents/jobs.
- Added forward-only migration
  `0005_organization_memberships`; the supported production Alembic head is
  now `0005_organization_memberships`.
- Added a regression test that creates two tenants and confirms a real
  non-development ADMIN membership can only list its own agents/jobs and is
  forbidden from another tenant's assets.
- Added organization ownership to audit and security-event records, including
  the audit-chain canonical payload for new tenant-tagged events. Central
  agent/job/policy/enrollment writes now pass the resolved organization ID.
- Tenant-filtered `GET /audit-logs` and `GET /security-events` now exclude
  records from other organizations and fail closed for legacy null-organization
  records. Legacy local-only `/jobs`, `/assets`, `/results`, and
  `/certificates` routes are explicitly global-scope-only until their records
  receive ownership fields.
- Added forward-only migration `0006_organization_event_scope`; production
  schema head is now `0006_organization_event_scope`.

## Modified files

- `backend/app/models.py`
- `backend/app/auth.py`
- `backend/app/schemas.py`
- `backend/app/routers/agents.py`
- `backend/app/main.py`
- `migrations/versions/0005_organization_memberships.py` (new)
- `tests/test_stage4_sync.py`
- `backend/app/routers/audit_logs.py`
- `backend/app/routers/security_events.py`
- `backend/app/routers/jobs.py`
- `backend/app/routers/devices.py`
- `backend/app/routers/results.py`
- `backend/app/routers/certificates.py`
- `backend/app/security.py`
- `backend/app/services.py`
- `migrations/versions/0006_organization_event_scope.py` (new)

## Validation performed

Passed:

```powershell
python -m compileall backend\app\auth.py backend\app\models.py backend\app\routers\agents.py backend\app\schemas.py migrations\versions\0005_organization_memberships.py tests\test_stage4_sync.py
git diff --check
python -c "from sqlalchemy import create_engine, inspect; from backend.app.db import Base; import backend.app.models; engine=create_engine('sqlite:///.tmp/tenant-schema.db'); Base.metadata.create_all(engine); assert 'organization_memberships' in inspect(engine).get_table_names(); print('OK')"
```

The focused pytest suite could be invoked after providing a workspace-local
`--basetemp`, but it cannot complete because the active Python interpreter does
not have `cryptography`; enrollment/signing tests fail with
`ModuleNotFoundError: No module named 'cryptography'`. This is an environment
dependency failure, not an asserted test failure. Do not claim the suite passes
until a project-local dependency environment is available.

`python -m alembic heads` also cannot run in this interpreter because Alembic
is missing. The configured application head is nevertheless updated to
`0007_remote_policy_lifecycle`.

The legacy backend API contract suite passes with the workspace-local pytest
base directory: `4 passed` (one existing Starlette/httpx deprecation warning).

The membership lifecycle regression passes independently: `1 passed`.

The latest pytest temporary directory (`.pytest-work`) could not be removed
because Windows denied access after the run; it is disposable and is not a
source change. Remove it when the lock clears before committing.

## Next work, in priority order

1. Complete tenant scoping for audit logs and security events. These records
   currently lack a reliable organization foreign key; add an additive field or
   normalized correlation and write tenant-filtered reads. Do not infer tenancy
   from mutable resource strings.
2. Scope or explicitly classify the legacy local-only routes (`/jobs`,
   `/assets`, `/results`, `/certificates`) before exposing them in a multi-tenant
   central deployment. Their underlying legacy records currently have no
   organization ownership, so non-global users should fail closed.
3. Add membership removal/disable lifecycle and authorization rules that make
   the stored membership role meaningful (currently role is recorded as
   `OWNER`/`MEMBER`; global operator roles still decide action type).
4. Run Alembic migration `0005` on SQLite and PostgreSQL using an approved
   project-local dependency environment, then run the full tests with a local
   pytest base temp directory.
5. Continue the existing policy/approval lifecycle work: rejection/cancel,
   approval expiry, real two-person/MFA tests, and security events.

## Security invariants retained

- No remote shell, arbitrary executable, argv, or shell fragments.
- Local independent approval remains required for destructive execution.
- Signed command verification, nonce replay protection, target identity, and
  mounted/system-disk safeguards remain unchanged.
- No tenant member may read or act on a legacy null-organization central
  resource; only the explicit global scope can access one.
- Existing production migrations remain forward-only. Back up production data
  before migration and do not backfill a default organization without an
  explicit product/upgrade decision.
