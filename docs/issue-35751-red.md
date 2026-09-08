# Issue 35751 RED Evidence

Test-only regression for resumed compacted Responses WebSocket tool loss.

The regression asserts that `Compaction` and `ContextCompaction` are context replacement boundaries and must not be serialized as an incremental websocket delta, while ordinary input extension remains incremental.