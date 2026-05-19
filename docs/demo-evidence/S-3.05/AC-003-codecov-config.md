# AC-003 — codecov.yml configuration

## Command
```
cat codecov.yml
```

## Output
```yaml
coverage:
  status:
    project:
      default:
        target: auto
        threshold: 1%
    patch:
      default:
        target: 70%
        threshold: 0%
comment:
  layout: "reach, diff, flags, files"
  behavior: default
  require_changes: true
ignore:
  - "tests/**"
  - "benches/**"
  - "fuzz/**"
  - "build.rs"
```

project target=auto (1% drop tolerance), patch target=70%, tests/benches/fuzz ignored.
