# Wraith v0.1.0 - Summary

**Wraith** is a native x64 debugger for Linux, written in C directly on the
`ptrace` syscall. It uses no debugging libraries, the DWARF parser,
disassembler, and stack unwinder are all hand written. It is built in the open
as a long running project for me to learn systems programming through a real
language like c.


## Key Features

Right now Wraith is Linux x86-64 only and it only debugs on the local machine.
It's early, v0.1.0 so expect it to be rough. If you hit a
crash or something reads wrong, open an issue, a reproduction helps me a lot.

What works right now:

- Attach to a running process by pid, and detach again
- Read the registers with rip/rsp/rbp/rax off a stopped tracee
- Source level breakpoints.
Stuff I still want to add:

- x64 disassembly and stack unwinding, hand written
- Thread safety
- multihreading
- remote debugging
- 
- A gui that isn't a browser based wrapper.

## From Scratch (Mostly)

I want to write everything a debugger normally pulls from a library by hand, the
DWARF parser, the x64 disassembler, the stack unwinder. That's the part I
actually want to learn.

The only thing I link is libc and I only use it as the c runtime:

- Used: stdio, unistd/sys/wait, sys/ptrace.h, sys/user.h. These know syscalls and io, not debugging.
- Banned: libdw/libdwarf for DWARF (has been written by hand, as well as line_table parsing in dwarf/line.c), libunwind for frames, capstone for disassembly, readline for line editing. Wraith does all of that itself.

To attach you need a matching uid and a permissive ptrace_scope (or
CAP_SYS_PTRACE), so in practice you'll run it as root.

## Build

make builds ./wraith. Then attach to a pid and dump its registers:

```
make
sudo ./wraith <pid>
```


## The Code

It's small and split by what each file does:

- src/main.c is the driver, the "ui" process. It parses the args and drives the session.
- include/process.h is the process control interface. It declares the tracee enum/struct, the launch/attach/wait/detach api and stop_reason.
- src/process.c is the ptrace layer, it implements process.h on top of raw ptrace. Both entry paths (launch and attach) go through here to reach a stopped tracee with a known pid.

## Licensing

MIT Licensed
