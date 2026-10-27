# PackFixer
Fixes slow resource pack loading in Minecraft for Windows (GDK build) running on Linux through [BedrockOnLinux](https://github.com/Wyze3306/BedrockOnLinux).

## What it does
Joining a server or world with resource packs keeps one core busy for minutes inside Wine's heap. Every time Wine's low fragmentation heap needs a new group for small objects, `heap_allocate_block` walks a free list bucket full of blocks that are slightly too small. `packfix_bump.dll` rewrites the calls to `heap_allocate_block` inside ntdll so that the block size is rounded up to the next free list bucket, where the first free block always fits. The game code is not touched.

## Setup
Download `packfix_bump.dll` from the latest release, then set these in `~/.local/share/bedrock-on-linux/settings.json` (or the injector options in the BedrockOnLinux GUI):

```json
{
  "injector_auto_enable": true,
  "injector_dll_type": "file",
  "injector_dll": "/path/to/packfix_bump.dll",
  "injector_delay": 15
}
```

The DLL picks its mode from its file name, so keep `bump` in the name. Any other name runs a report-only mode that patches nothing.

Optional environment variables, set through `custom_env` (no spaces or backslashes inside values, BedrockOnLinux splits it with `shlex`):

* `PACKFIX_LOG`: log file path. Defaults to `packfix.log` next to the DLL.
* `PACKFIX_DELAY`: milliseconds to wait before patching, and between log rounds. Default 5000.
* `PACKFIX_WINDOW`: milliseconds to keep writing log rounds. Default 300000. The patch stays in place after that.

## Notes

* Tested with BedrockOnLinux's pinned WineGDK (Wine 11.1) and Minecraft 1.26.52.3.
* The DLL finds `heap_allocate_block` by a byte signature of its free list loop and `.pdata`, so it does not depend on fixed offsets. If the signature is not found exactly once, it logs `bump abort` and leaves ntdll alone; the game then loads packs at the usual speed.
* A healthy log has `bump init ... calls=N` followed by `bump site ... patched` lines, and `bump n=` growing while you join a server.
* Call sites that straddle a 16 byte boundary cannot be swapped atomically and are skipped (`skipped` in the log).

## Build from source

Requirements: LLVM (`clang-cl`, `lld-link`, `llvm-lib`, `llvm-rc`, `llvm-mt`; tested with 21), CMake 4.3+, Ninja, and the Windows SDK and CRT from [xwin](https://github.com/Jake-Shadle/xwin). Running xwin means accepting the Microsoft license.

```bash
xwin --accept-license splat --output ~/.xwin
cmake --preset release
cmake --build --preset release
```

The toolchain picks the newest `/usr/lib/llvm-*/bin` and `~/.xwin`; set `LLVM_BIN` or `XWIN_DIR` to override. Build outputs are generated in `build/release/`: `packfix_bump.dll`, plus `scan_bench.exe` and `packfix_test.exe` for checking a build under Wine.
