# Wraith v0.1.0 - Summary

**Wraith** is a native x64 debugger for Linux, written in C directly on the
`ptrace` syscall. It uses no debugging libraries, the DWARF parser,
disassembler, and stack unwinder are all hand written. It is built in the open
as a long running project for me to learn systems programming through a real
language like c.

I want to learn more about the linux kernel and apply this knowledge to more sys programming.
As a goal I also want to implement a GUI with a usable and quick interface that isn't actual
torture to use like some others, and should be a reliable alternative to printf debugging.
Meaning it has a learning aspect to it aswell.

## Key Features

Right now Wraith is Linux x86-64 only and it only debugs on the local machine.
It's early, v0.1.0 is just milestone 1, so expect it to be rough. If you hit a
crash or something reads wrong, open an issue, a reproduction helps me a lot.

What works right now:

- Attach to a running process by pid (PTRACE_ATTACH + waitpid) and detach again
- Read the registers with PTRACE_GETREGS, rip/rsp/rbp/rax off a stopped tracee

Stuff I still want to add:

- Launch mode (fork + PTRACE_TRACEME + exec), it's stubbed for now
- Breakpoints and single stepping
- DWARF parsing so I can do source level debugging
- x64 disassembly and stack unwinding, hand written
- A gui

## From Scratch

I want to write everything a debugger normally pulls from a library by hand, the
DWARF parser, the x64 disassembler, the stack unwinder. That's the part I
actually want to learn.

The only thing I link is libc and I only use it as the c runtime:

- Used: stdio, unistd/sys/wait, sys/ptrace.h, sys/user.h. These know syscalls and io, not debugging.
- Banned: libdw/libdwarf for DWARF, libunwind for frames, capstone for disassembly, readline for line editing. Wraith does all of that itself.

To attach you need a matching uid and a permissive ptrace_scope (or
CAP_SYS_PTRACE), so in practice you'll run it as root.

## Build

make builds ./wraith. Then attach to a pid and dump its registers:

```
make
sudo ./wraith <pid>
```

## Roadmap

The next thing is getting launch mode up to where attach already is. Attach
already lands on a stopped tracee, launch needs to get to the same place through
fork + PTRACE_TRACEME + exec. Once both of them end up on a stopped tracee with
a known pid I can start on breakpoints and single stepping.

After that I want the from scratch parts, DWARF parsing first for symbols and
line info, then x64 disassembly, then stack unwinding. Source level debugging
comes out of those. The big long term goal is the gui.

## The Code

It's small and split by what each file does:

- src/main.c is the driver, the "ui" process. It parses the args and drives the session, the front end grows here.
- include/process.h is the process control interface. It declares the tracee enum/struct, the launch/attach/wait/detach api and stop_reason.
- src/process.c is the ptrace layer, it implements process.h on top of raw ptrace. Both entry paths (launch and attach) go through here to reach a stopped tracee with a known pid.

## Licensing

MIT Licensed
