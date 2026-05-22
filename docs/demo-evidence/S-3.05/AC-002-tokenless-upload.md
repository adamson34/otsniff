# AC-002 — Tokenless upload (no CODECOV_TOKEN secret)

## Command
```
grep -B1 -A4 "codecov/codecov-action@v4" .github/workflows/ci.yml | head -10
```

## Output
```
      - name: Upload to codecov
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: false
```

No `token:` input present — public-repo OIDC tokenless upload; no secret to manage.
