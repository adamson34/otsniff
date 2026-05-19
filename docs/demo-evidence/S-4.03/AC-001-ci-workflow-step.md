# AC-001: CI Workflow Step — map_value_substring

Source: `grep -B1 -A3 "map_value_substring" .github/workflows/kani.yml`

```
      - name: Run map value substring proof
        run: cargo kani --harness map_value_substring
        timeout-minutes: 30
```
