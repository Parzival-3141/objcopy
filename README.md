# `zig objcopy` [rewrite](https://github.com/ziglang/zig/issues/24522)

Goal: Support the most common operations on the most common object formats.

## Architecture
Define an API for manipulating objects and provide implementations for each supported format. 

Conversion between object formats (besides "raw" formats like `binary`, `ihex`, etc.) is intentionally unsupported.
This feature is rarely used and requires a huge amount of complexity in return. GNU is the only vendor that implements it and built a dedicated library (BFD) to do it.
LLVM drops this feature as well, although it does support converting between ELF types (endianness, architecture, 32/64bit).

Primitives:
 - Sections
 - Symbols
 - Relocations(?)

Operations:
 - Add
 - Remove
 - Configure (Sections only?)
 - Compress  (Sections only)

Formats:
 - Binary (raw program image)
 - Intel Hex
 - ELF
 - MachO
 - COFF/PE(?)

Should also support:
 - `--set-section-flags` and other general flags when copying ELF to RAW or HEX. Or really, all options should be reasonably supported regardless of input or output file format.
 - [elf to elf copying](https://github.com/ziglang/zig/issues/14717)
 - [ability to output raw binary or hex format rather than ELF](https://github.com/ziglang/zig/issues/2826)

Is this design sound? Are there pitfalls that I'm missing, perhaps related to object formats?

https://sourceware.org/binutils/docs/ld/BFD.html
https://gabi.xinuos.com/elf/
https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779
https://groups.google.com/g/llvm-dev/c/obPlL1dU8OM
https://maskray.me/blog/2024-01-14-exploring-object-file-formats


## General Options

[`--add-section <section>=<file>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-add-section) \
    Add a section named `<section>` with the contents of `<file>` to the output. Can be specified multiple times to add multiple sections.

[`--add-gnu-debuglink <debug-file>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-add-gnu-debuglink) \
    Creates a `.gnu_debuglink` section which contains a reference to `<debug-file>` and adds it to the output file.

[`--only-keep-debug`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-only-keep-debug) \
    Strip a file, removing contents of any sections that would not be stripped by `--strip-debug` and leaving the debugging sections intact.

[`--only-section <section>, -j`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-only-section) \
    Remove all sections from the output, except for sections named `<section>`. Can be specified multiple times to keep multiple sections.

[`--output-target <format>, -O`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-output-target) \
    Write the output as the specified format. If unspecified, the output format is assumed to be the same as the input file’s format. 

[`--remove-section <section>, -R`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-remove-section) \
    Remove the specified section from the output. Can be specified multiple times to remove multiple sections simultaneously.

[`-set-section-alignment <section>=<align>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-set-section-alignment) \
    Set the alignment of section `<section>` to `<align>`. `<align>` must be a power of two. Can be specified multiple times to update multiple sections. 

[`--set-section-flags <section>=[<flags>]`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-set-section-flags) \
    Set flags of `<section>` to `<flags>`, represented as a comma separated list. If `<flags>` is empty, all unpreserved flags will be cleared. Can be specified multiple times to update multiple sections.

[`--strip-all, -S`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-all) \
    Remove all debug sections and symbol table from the output.

[`--strip-debug, -g`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-debug) \
    Remove all debug sections from the output.
   
[`--strip-symbol <symbol>, -N`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-symbol) \
    Remove all symbols named `<symbol>` from the output. Can be specified multiple times to remove multiple symbols.

(Maybe add `--strip-unneeded` too?)


## Elf Specific Options
[`--compress-debug-sections`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-compress-debug-sections) \
    Compress DWARF debug sections with zlib. (Note llvm-objcopy supports using zstd)

[`--pad-to <address>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-pad-to) \
    For binary outputs, pad the output to the load address `<address>` using a value of zero.

[`--strip-dwo`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-dwo) \
    Remove all DWARF `.dwo` sections from the output.


## Zig Specific Options
`--extract-to <file>` \
    Extract the removed sections into `<file>`, and add a `.gnu-debuglink` section.


## Old Zig Options
```
Usage: zig objcopy [options] input output

Options:
  -h, --help                              Print this help and exit
  --output-target=<value>                 Format of the output file
  -O <value>                              Alias for --output-target
  --only-section=<section>                Remove all but <section>
  -j <value>                              Alias for --only-section
  --pad-to <addr>                         Pad the last section up to address <addr>
  --strip-debug, -g                       Remove all debug sections from the output.
  --strip-all, -S                         Remove all debug sections and symbol table from the output.
  --only-keep-debug                       Strip a file, removing contents of any sections that would not be stripped by --strip-debug and leaving the debugging sections intact.
  --add-gnu-debuglink=<file>              Creates a .gnu_debuglink section which contains a reference to <file> and adds it to the output file.
  --extract-to <file>                     Extract the removed sections into <file>, and add a .gnu-debuglink section.
  --compress-debug-sections               Compress DWARF debug sections with zlib
  --set-section-alignment <name>=<align>  Set alignment of section <name> to <align> bytes. Must be a power of two.
  --set-section-flags <name>=<file>       Set flags of section <name> to <flags> represented as a comma separated set of flags.
  --add-section <name>=<file>             Add file content from <file> with the a new section named <name>.
```
