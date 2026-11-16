---
name: zig
description: "Write correct, idiomatic Zig 0.17 code. Use when writing new Zig code, editing existing Zig files, debugging Zig compilation errors, reviewing Zig code, or working with build.zig files. Triggers on any task involving .zig files. Critical: LLM training data contains outdated Zig patterns (0.11-0.15) that will produce broken code — this skill points at the current 0.17 guidance."
---

# Zig

The org skill `zig-017` is the authority. Read its `references/zig-0.17.md`
before the first Zig file, and `references/zig-0.17-changes.md` when a build
fails. This file exists so the skill is discoverable from this directory; do
not fork the guidance here again.

Rule zero: verify APIs against the pinned toolchain, not memory.

```bash
zigdoc <symbol>        # toolchain-aware API discovery
zig env                # .std_dir = the std source for THIS compiler
ziglint-0-17 src/      # style and correctness lint
```

If a capability seems missing, grep `.std_dir` for where it moved before
hand-rolling it. 0.16 relocated huge API surfaces without renaming the
capability, and 0.17 moved more.

## The 0.17 floor, in one line each

- `@cImport` is gone; use `b.addTranslateC` and `const c = @import("c")`.
- Array multiplication `**` is gone; build repeated bytes with a loop or `@memcpy`.
- `zig fmt` and ziglint prefer `std.mem.print` over `std.bufPrint`, and `Allocator.print` over `allocPrint`.
- `@intFromEnum` is spelled `@backingInt` in 0.17, and `zig fmt` rewrites it.
- `Build.Step.Run` gained `addPassthruArgs`; 0.16 has no such member.
- `ziglint-0-17` replaces `ziglint-0-16`.
