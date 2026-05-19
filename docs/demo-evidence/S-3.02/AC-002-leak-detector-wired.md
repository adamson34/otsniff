# AC-002 Leak Detector Wired — Evidence

## grep -n "leak|IP.*pattern|MAC.*pattern" tests/prompt-evals/run_all.sh

```
61:# Leak detector helper: scan text for real IP/MAC patterns (EC-002)
63:leak_check() {
66:    # IPv4 pattern
68:        echo "FAIL [$name]: leak detector tripped — response contains IPv4 address" >&2
71:    # MAC address pattern
73:        echo "FAIL [$name]: leak detector tripped — response contains MAC address" >&2
218:    # EC-002: run leak detector on response
219:    if ! leak_check "$response" "$name"; then
220:        echo "FAIL [$name]: leak detector tripped on claude response"
```
