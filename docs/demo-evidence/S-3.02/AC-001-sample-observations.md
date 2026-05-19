# AC-001 Sample Observations — Evidence

## head -40 tests/prompt-evals/span/observations.json

```json
{
  "capture_source": "Span",
  "hosts": {
    "host_001": {
      "ip": "host_001",
      "macs": [[0, 80, 86, 1, 2, 3]],
      "protocols": ["Modbus/TCP", "TCP"],
      "first_seen": "2024-01-15T08:00:00Z",
      "last_seen": "2024-01-15T08:30:00Z",
      "packets": 1240,
      "bytes": 98560,
      "in_ot_zone": true
    },
    "host_002": {
      "ip": "host_002",
      "macs": [[0, 80, 86, 4, 5, 6]],
      "protocols": ["Modbus/TCP", "TCP"],
      "first_seen": "2024-01-15T08:00:00Z",
      "last_seen": "2024-01-15T08:30:00Z",
      "packets": 840,
      "bytes": 52480,
      "in_ot_zone": true
    },
    "host_003": {
      "ip": "host_003",
      "macs": [[0, 80, 86, 7, 8, 9]],
      "protocols": ["TCP", "HTTP"],
      "first_seen": "2024-01-15T08:05:00Z",
      "last_seen": "2024-01-15T08:25:00Z",
      "packets": 320,
      "bytes": 18200,
      "in_ot_zone": false
    }
  },
  "flows": {
    "host_001->host_002:502/tcp": {
      "key": {
        "src": "host_001",
        "dst": "host_002",
        "dst_port": 502,
```
