# AC-003: Byte Buffer Unchanged

## Structural Note

AC-003 ("unscrub-and-render pipeline still operates on full response byte buffer")
is structural rather than behavioral: the heartbeat machinery accumulates the
subprocess stdout into a `Vec<u8>` on the background thread and returns it to
the caller intact. The existing `analyze()` path then converts the complete
buffer via `String::from_utf8` exactly as before — no partial or mid-stream
display occurs, preserving the ADR-0007 privacy contract (the full response
must pass through the leak detector before any rendering).

## Diff Evidence: `String::from_utf8` call site unchanged

```
git diff 7556939..HEAD -- src/ai/claude_cli.rs | grep -A2 "String::from_utf8"
```

```
+                let stderr_text = String::from_utf8_lossy(&output.stderr);
+                return Err(OtError::Parse(format!(
+                    "claude exited with code {:?}: {}",
--
+        String::from_utf8(response_bytes)
+            .map_err(|e| OtError::Parse(format!("claude stdout was not valid UTF-8: {e}")))
+    }
--
-            let stderr = String::from_utf8_lossy(&output.stderr);
-            return Err(OtError::Parse(format!(
-                "claude exited with code {:?}: {}",
--
-        String::from_utf8(output.stdout)
+        let elapsed = now.duration_since(start);
--
+        let output = String::from_utf8(writer).unwrap();
+        assert!(
+            output.matches("still working").count() >= 3,
--
+        let output = String::from_utf8(writer).unwrap();
+        assert!(
+            !output.contains("still working"),
--
+        let output = String::from_utf8(writer).unwrap();
+        assert!(
+            output.contains("4127 bytes"),
--
+            String::from_utf8_lossy(&writer)
+        );
+    }
```

The terminal conversion `String::from_utf8(response_bytes)` (new) corresponds
directly to the removed `String::from_utf8(output.stdout)` (old); the call site
and error-handling shape are identical.
