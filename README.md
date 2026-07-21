# Wraith v0.1.0 - Summary

**Wraith** is a native x64 debugger for Linux, written in C directly on the
`ptrace` syscall. It uses no debugging libraries — the DWARF parser,
disassembler, and stack unwinder are all hand-written, claude is used for documentation
and research for the project. It is built in the open as a long running project for me
to learn systems programming through a real language like c.

I want to learn more about the linux kernel and apply this knowledge to more sys programming.
As a goal I also want to implement a GUI with a usable and quick interface that isn't actual
torture to use like some others, and should be a reliable alternative to printf debugging.
Meaning it has a learning aspect to it aswell.

## Key Features

**Foundation:**
- Built directly on `ptrace` — no VM, no toy bytecode; debugs real native ELF binaries
- Launch (fork + `PTRACE_TRACEME` + exec) or attach to a running PID
- Raw register access via `PTRACE_GETREGS`

**From scratch:**
- DWARF parsing, x64 disassembly, and stack unwinding all hand-written
- Zero debugging libraries — see [Dependencies](#dependencies)

## Milestones

Milestones track the chapters of *Building a Debugger* by Sy Brand
(No Starch Press, 2025).

| # | Milestone | Book |
|---|-----------|------|
| 1 | Attach to a process, read its registers raw | 3, 5 |
| 2 | Software breakpoints — one `0xCC` byte, one `SIGTRAP` | 7, 8 |
| 3 | Signals and syscalls — trace and catch | 10 |
| 4 | Symbols and source lines from DWARF | 11–13 |
| 5 | Shared libraries — symbols across `.so` boundaries | 17 |
| 6 | Stepping — over, into, out | 14 |
| 7 | Reading variables from registers and the stack | 19, 20 |
| 8 | The call stack — a real backtrace | 15, 16 |
| 9 | Watchpoints via hardware debug registers | 9 |
| 10 | Multithreading — per-thread stops | 18 |
| 11 | Remote debugging across machines | 22 |

Beyond the book: chapter 22 surveys advanced topics it never implements —
remote debugging, reverse (time-travel) execution, non-stop mode. Concrete
targets are tracked per milestone in `notes/`.

## Current Limitations

- Linux x86-64 only
- Attach requires a matching UID and permissive `ptrace_scope`/`CAP_SYS_PTRACE` — usually run as root
- v0.1.0 implements milestone 1 only; launch mode is still stubbed

## Dependencies

libc only, used strictly as the C runtime:

- **Used** — `stdio`, `unistd`/`sys/wait`, `sys/ptrace.h`, `sys/user.h`. These know syscalls and I/O, not debugging.
- **Banned** — `libdw`/`libdwarf` (DWARF), `libunwind` (frames), `capstone` (disassembly), `readline` (line editing). Wraith writes all of these by hand.

## Build

```
make                 # builds ./wraith
./wraith <pid>       # attach to a running process, dump registers
```

## Licensing

TBD.
