# Contributing to Ospysin

Thank you for contributing to Ospysin. To preserve architectural integrity, all contributions must strictly adhere to our engineering standards.

---

## Core Philosophy & Cardinal Rules

1. **Documentation-First**: No new feature PR is merged without corresponding updates to `docs/`.
2. **User-Driven Invariant**: Never introduce autonomous agent loops or automatic tool executions.
3. **Local-First Invariant**: Never introduce dependencies requiring external cloud APIs or third-party tracking.
4. **Network Safety First**: Any modification touching network code must pass `PolicyEngine` unit and integration tests.

---

## Development Workflow

1. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feat/add-new-inspection-tool
   ```
2. Ensure all changes adhere to project formatting:
   - Java: 4 spaces, UTF-8, no wildcard imports.
   - Frontend: 2 spaces, TypeScript strict mode, Vue 3 Composition API with `<script setup>`.
3. Verify tests pass locally:
   ```bash
   ./mvnw clean test
   cd frontend && pnpm test
   ```

---

## Commit Message Conventions

We enforce [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` A new user-facing capability or inspection tool.
- `fix:` A bug fix or security patch.
- `docs:` Documentation additions or updates.
- `test:` Adding or updating test suites.
- `refactor:` Code reorganization without behavioral change.
- `chore:` Build scripts, dependency bumps, or tool configurations.

Example:
```text
feat(tools): add whois referral depth limit
docs(policy): update private subnet range definitions
```
