# `zig objcopy` [rewrite](https://github.com/ziglang/zig/issues/24522)

## Architecture
I see two ways of doing this, either create an API for manipulating objects and provide implementations for each format, or parse to an homogenous internal format and operate on that.

Seperate input and output formats from internal format. Operations on object contents should be largely agnostic to the final output format.

Primitives:
 - Sections
 - Symbols
 - Relocations(?)

Operations:
 - Add
 - Remove
 - Configure (Sections only)
 - Compress  (Sections only)

Formats:
 - Binary (raw)
 - ELF
 - MachO
 - COFF/PE(?)

Should also support:
 - `--set-section-flags` and other general flags when copying ELF to RAW or HEX. Or really, all options should be reasonably supported regardless of input or output file format.
 - [elf to elf copying](https://github.com/ziglang/zig/issues/14717)
 - [ability to output raw binary or hex format rather than ELF](https://github.com/ziglang/zig/issues/2826)

Is this design sound? Are there pitfalls that I'm missing, perhaps related to object formats?

Optional: create reusable helper libraries for the formats and operations?

https://sourceware.org/binutils/docs/ld/BFD.html
https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779


## General Options

[`--add-section <section>=<file>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-add-section) \
    Add a section named `<section>` with the contents of `<file>` to the output. 

[`--add-gnu-debuglink <debug-file>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-add-gnu-debuglink) \
    Creates a `.gnu_debuglink` section which contains a reference to `<debug-file>` and adds it to the output file.


[`--only-keep-debug`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-only-keep-debug) \
    Strip a file, removing contents of any sections that would not be stripped by `--strip-debug` and leaving the debugging sections intact.

[`--only-section <section>, -j`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-only-section) \
    Remove all sections from the output, except for sections named `<section>`. Can be specified multiple times to keep multiple sections.

[`--remove-section <section>, -R`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-remove-section) \
    Remove the specified section from the output. Can be specified multiple times to remove multiple sections simultaneously.

[`-set-section-alignment <section>=<align>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-set-section-alignment) \
    Set the alignment of section `<section>` to `<align>`. `<align>` must be a power of two. Can be specified multiple times to update multiple sections. 

[`--set-section-flags <section>=<flag>[,<flag>,...]`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-set-section-flags) \
    Set flags of `<section>` to `<flags>` represented as a comma separated set of flags.

[`--strip-all, -S`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-all) \
    Remove all debug sections and symbol table from the output.

[`--strip-debug, -g`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-debug) \
    Remove all debug sections from the output.
   
[`--strip-symbol <symbol>, -N`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-symbol) \
    Remove all symbols named `<symbol>` from the output. Can be specified multiple times to remove multiple symbols.

Maybe strip-unneeded?

## Elf Specific Options
[`--compress-debug-sections`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-compress-debug-sections) \
    Compress DWARF debug sections with zlib. (Note llvm-objcopy supports using zstd)

[`--output-target <format>, -O`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-output-target) \
    Format of the output file

[`--pad-to <address>`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-pad-to)
For binary outputs, pad the output to the load address `<address>` using a value of zero.

[`--strip-dwo`](https://llvm.org/docs/CommandGuide/llvm-objcopy.html#cmdoption-llvm-objcopy-strip-dwo) \
    Remove all DWARF `.dwo` sections from the output.


## Zig Additions
`--extract-to <file>` \
    Extract the removed sections into `<file>`, and add a .gnu-debuglink section.



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
