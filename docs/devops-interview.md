# CI/CD troubleshooting and interview notes

## Common failures

| Symptom | What to check |
| --- | --- |
| `npm ci` fails | Use Node 20.19+; confirm the lockfile matches its package manifest. Correct dependency changes locally and commit both files; never replace CI with `npm install`. Check registry access and native Argon2 install output. |
| Frontend lint/build fails | Run `npm run lint` and `npm run build` in `frontend/`. Read the first error. A Docker build also runs Vite, so it may expose the same problem. |
| Backend cannot import/start | Run `npm run check` in `backend/`. Check native Argon2 availability and that `src/data/common-passwords.txt` exists. The integration suite starts the real entrypoint and fails if it exits or never becomes healthy. |
| PostgreSQL connection failure | In Actions check the service health logs, `127.0.0.1:5432`, and matching service/job credentials. In Compose use the service hostname `db`; `localhost` inside the backend points to the backend container. |
| Relation/table missing | Confirm `npm run db:test:prepare` succeeded. Compose init SQL only runs on a fresh volume; apply the schema explicitly to an existing database. |
| Test refuses to run | It needs explicit variables, `NODE_ENV=test`, database name ending `_test`, a 64-hex key and `COOKIE_SECURE=true`. Never point it at a valuable database. |
| TOTP test fails or takes time | Enrollment consumes a time-step. A wait up to 30 seconds is expected. Check host time, the first failed assertion, encryption-key validity and database readiness; do not remove replay checks or substitute a passing mock. |
| Compose is unhealthy / nginx returns 502 | Run `docker compose ps --all` and `docker compose logs --tail=100 backend frontend db`. Check backend health and schema initialization. Make sure nginx and backend share the Compose network and `backend:5000` resolves. |
| Cookies disappear locally | Root example uses `COOKIE_SECURE=false` only for loopback HTTP. Hosted HTTPS must use `true`. Browser and API must share the nginx origin. |
| Unexpected authentication 429 behind nginx | The current Express application uses the proxy's source IP. Source budgets are shared until explicit trusted-proxy handling is designed; do not disable the limiter to hide this. |
| Changed database password stops working | Existing volumes keep PostgreSQL's original role credentials. Editing `.env` does not execute `ALTER ROLE`. Preserve valuable data and manage the role deliberately. |
| GHCR denied / `write_package` forbidden | Check `packages: write`, organization policy and the package's Actions repository access. Existing packages may not inherit this repository's access automatically. |
| CD does not run | Both workflows must be on default branch `main`. CI must complete successfully from a same-repository **push** to main, not a PR or manual dispatch. Check the exact workflow name `CI`. |
| Old rerun has no `latest` tag | Expected if main advanced. It still receives the tested commit's SHA tag. |
| One image published and the other failed | Publication is a two-job matrix, not an atomic transaction. Fix the failure and rerun the failed job; use matching commit SHA tags for a release. |

Do not paste `.env`, cookie jars, setup keys or access tokens into issue reports. The workflow does not dump environment variables or render full Compose configuration into logs.

## Interview explanation

“I added GitHub Actions around an existing MFA application without rewriting authentication. Each pull request runs frontend lint/build, real backend HTTP tests against PostgreSQL 16, and production Docker builds with a Compose smoke test. A required check blocks merging when any job fails. After successful CI for a main-branch push, a separate delivery workflow checks out that exact tested commit and publishes backend and frontend images to GHCR with commit SHA tags and a guarded latest tag. It uses GitHub's built-in token with package-write permission only in delivery. Secrets stay out of Git and Docker build contexts. This is continuous delivery; deploying those images to a hosting platform is a separate step.”

## Likely questions and answers

1. **Why separate CI from CD?** CI validates changes, including untrusted pull requests, with read-only repository permission. CD has package-write permission only after successful trusted-main CI. Separating them makes the release boundary explicit.

2. **How do you ensure CD builds the tested commit?** `workflow_run.head_sha` identifies the commit CI tested. CD checks out that exact SHA and uses it in image tags and revision labels. The default `github.sha` for a workflow-run event can point to a different default-branch commit.

3. **Why use `npm ci` instead of `npm install`?** It installs the lockfile's dependency graph and fails if the manifest and lockfile disagree. Each package directory installs once per Node CI job. npm caches downloads, while Docker maintains its own layer cache.

4. **Why a real PostgreSQL service instead of mocks?** Session transactions, constraints, token lookup, advisory/row locking and SQL syntax are part of this application. A disposable PostgreSQL 16 instance tests that integration. These tests are not substitutes for every concurrency or load test.

5. **How do the tests prove MFA is required?** Registration and correct-password requests must still get 401 from the dashboard. The suite performs actual TOTP enrollment and login, observes a full session only after the second factor, rejects a replayed code and rejects a logged-out token.

6. **Why multi-stage Dockerfiles and non-root users?** Build tools and frontend development dependencies are used only in build stages. Runtime images contain the application and production dependencies/static assets. Non-root users, read-only filesystems and dropped capabilities reduce runtime privileges.

7. **How are secrets handled?** Runtime database passwords and encryption keys come from environment configuration and are excluded from Git/build contexts. CI has an isolated disposable database and generated test key. GHCR uses the automatic `GITHUB_TOKEN`; no production secret is needed to test or build images.

8. **Why both SHA tags and `latest`? How would you roll back?** SHA tags identify a source revision and let both components use the same version. `latest` is convenient but mutable. A future deployment can select an earlier tested version; image digests provide exact immutable content identity. Database compatibility must also be checked before rollback. No rollback deployment is implemented here.

9. **What does a green pipeline not prove?** It proves the checks actually executed in that run. It does not prove complete browser MFA/recovery integration, browser cookie policy enforcement, all attack scenarios, production scalability or a running deployment. Existing integration gaps are documented.

10. **What would you do before production deployment?** Select a host and supported Node LTS, configure HTTPS, deliberate proxy trust, secret management and least-privilege database access, add migration/backup/rollback procedures and monitoring, and complete the remaining application integration. CD currently ends at GHCR because no hosting infrastructure is configured.
