## What does this change?

<!-- 1-3 sentences. Link to an issue if applicable. -->

## Why?

<!-- The user-visible problem or motivation. Not the implementation. -->

## How was it tested?

- [ ] Unit / integration tests added or updated
- [ ] Manually verified (describe below)

```
# paste the smoke commands you ran
```

## Security review (for any change touching policy, audit, redaction, or the proxy)

- [ ] No change weakens fail-closed behavior
- [ ] Verdicts remain deterministic for identical inputs
- [ ] Redaction still applied before any log write
- [ ] Audit chain still verifiable (`airlock verify` passes)

## Checklist

- [ ] Conventional Commit title (`feat:`, `fix:`, `docs:`, etc.)
- [ ] `npm run lint && npm run typecheck && npm test && npm run build` all pass
- [ ] Updated docs if user-visible behavior changed
- [ ] No secrets, no telemetry, no network calls home
