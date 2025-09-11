const std = @import("std");
const elf = std.elf;

const fatal = std.process.fatal;

const help =
    \\Usage: zig objcopy [options] input output
    \\
    \\Options:
    \\  -h, --help                              Print this help and exit.
    \\  -O, --output-target <format>            Write the output as the specified format. If unspecified, the output format is assumed to be the same as the input file’s format.
    \\  --set-section-flags <section>=<flags>   Set flags of <section> to <flags>, represented as a comma separated list. Can be specified multiple times to update multiple sections.
;

pub fn main() !void {
    var arena_inst: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var args = try std.process.argsWithAllocator(arena);
    _ = args.skip();

    var opt_output_target: ?std.Target.ObjectFormat = null;
    var opt_set_section_flags: std.ArrayList(SetSectionFlags) = .empty;
    var opt_input: ?[]const u8 = null;
    var opt_output: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (!std.mem.startsWith(u8, arg, "-")) {
            if (opt_input == null)
                opt_input = arg
            else if (opt_output == null)
                opt_output = arg
            else
                fatal("unexpected positional argument: '{s}'", .{arg});
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            return std.debug.print("{s}\n", .{help}); // @Todo print to stdout
        } else if (std.mem.eql(u8, arg, "-O") or std.mem.eql(u8, arg, "--output-target")) {
            const opt = args.next() orelse fatal("expected another argument after '{s}'", .{arg});
            opt_output_target =
                if (strEql(opt, "binary"))
                    .raw
                else if (strEql(opt, "coff"))
                    .coff
                else if (strEql(opt, "elf"))
                    .elf
                else if (strEql(opt, "hex"))
                    .hex
                else
                    fatal("unrecognized object format: {s}", .{opt});
        } else if (std.mem.eql(u8, arg, "--set-section-flags")) {
            const opt = args.next() orelse fatal("expected another argument after '{s}'", .{arg});
            const split = splitOption(opt) orelse fatal("unrecognized argument: '{s}', expected <section>=<flags>", .{opt});

            var flags: SectionFlags = .{};
            if (split.second.len > 0) {
                var iter = std.mem.splitScalar(u8, split.second, ',');
                while (iter.next()) |flag| {
                    if (flag.len == 0) continue;
                    inline for (@typeInfo(SectionFlags).@"struct".fields) |field| {
                        if (strEql(flag, field.name)) {
                            @field(flags, field.name) = true;
                            break;
                        }
                    } else std.log.warn("skipping unrecognized section flag: '{s}'", .{flag});
                }
            }

            try opt_set_section_flags.append(arena, .{ .section_name = split.first, .flags = flags });
        } else fatal("unrecognized argument: '{s}'", .{arg});
    }

    const input = opt_input orelse fatal("expected input argument", .{});
    const output = opt_output orelse fatal("expected output argument", .{});

    // @Incomplete guess/detect input object format
    const input_ofmt: std.Target.ObjectFormat = .elf;
    const output_ofmt = opt_output_target orelse input_ofmt;
    _ = output_ofmt; // autofix

    // @Todo Should we read the entire file into memory or seek & read as needed?
    const input_file = std.fs.cwd().openFile(input, .{}) catch |err|
        fatal("failed to open {s}: {t}", .{ input, err });
    defer input_file.close();

    const output_file = try std.fs.cwd().createFile(output, .{});
    defer output_file.close();

    const elf_obj = try input_file.readToEndAlloc(arena, 1024 * 1024 * 1024);
    var reader: std.Io.Reader = .fixed(elf_obj);

    const elf_hdr = try elf.Header.read(&reader);
    std.debug.print("{}\n", .{elf_hdr});

    const sh_strtab: elf.Elf64_Shdr = table: {
        const size: u64 = if (elf_hdr.is_64) @sizeOf(elf.Elf64_Shdr) else @sizeOf(elf.Elf32_Shdr);
        const offset = elf_hdr.shoff + size * elf_hdr.shstrndx;
        var sh_reader = std.Io.Reader.fixed(elf_obj[offset..]);
        break :table try takeShdr(&sh_reader, elf_hdr);
    };

    const string_table: []const u8 = elf_obj[sh_strtab.sh_offset..][0..sh_strtab.sh_size];

    var iter = elf_hdr.iterateSectionHeadersBuffer(elf_obj);
    while (try iter.next()) |_section| {
        var section = _section;
        std.debug.assert(section.sh_name < string_table.len);

        const sh_name: []const u8 = if (section.sh_name != 0)
            std.mem.sliceTo(string_table[section.sh_name..], 0)
        else
            "";

        for (opt_set_section_flags.items) |set_flags| {
            if (strEql(set_flags.section_name, sh_name)) {
                setSectionFlags(&section, set_flags.flags, elf_hdr.machine == .X86_64);
            }
        }

        std.debug.print("{f}\n", .{
            DumpSection{ .section = &section, .string_table = string_table },
        });
    }
    // @Incomplete actually save changes
    var out_writer = output_file.writer(&.{});
    try out_writer.interface.writeAll(elf_obj);
    try out_writer.interface.flush();
}

const SplitResult = struct { first: []const u8, second: []const u8 };

fn splitOption(option: []const u8) ?SplitResult {
    const separator = '=';
    if (option.len < 3) return null; // minimum "a=b"
    for (1..option.len - 1) |i| {
        if (option[i] == separator) return .{
            .first = option[0..i],
            .second = option[i + 1 ..], // cannot overflow
        };
    }
    return null;
}

test splitOption {
    {
        const split = splitOption(".abc=123");
        try std.testing.expect(split != null);
        try std.testing.expectEqualStrings(".abc", split.?.first);
        try std.testing.expectEqualStrings("123", split.?.second);
    }

    try std.testing.expectEqual(null, splitOption(""));
    try std.testing.expectEqual(null, splitOption("abc"));
    try std.testing.expectEqual(null, splitOption("abc="));
    try std.testing.expectEqual(null, splitOption("=abc"));
}

fn strEql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn takeShdr(reader: *std.Io.Reader, elf_header: elf.Header) !elf.Elf64_Shdr {
    if (elf_header.is_64) {
        const shdr = try reader.takeStruct(elf.Elf64_Shdr, elf_header.endian);
        return shdr;
    }

    const shdr = try reader.takeStruct(elf.Elf32_Shdr, elf_header.endian);
    return .{
        .sh_name = shdr.sh_name,
        .sh_type = shdr.sh_type,
        .sh_flags = shdr.sh_flags,
        .sh_addr = shdr.sh_addr,
        .sh_offset = shdr.sh_offset,
        .sh_size = shdr.sh_size,
        .sh_link = shdr.sh_link,
        .sh_info = shdr.sh_info,
        .sh_addralign = shdr.sh_addralign,
        .sh_entsize = shdr.sh_entsize,
    };
}

const SetSectionFlags = struct {
    section_name: []const u8,
    flags: SectionFlags,
};

const SectionFlags = struct {
    alloc: bool = false,
    load: bool = false,
    noload: bool = false,
    readonly: bool = false,
    exclude: bool = false,
    debug: bool = false,
    code: bool = false,
    data: bool = false,
    rom: bool = false,
    share: bool = false,
    contents: bool = false,
    merge: bool = false,
    strings: bool = false,
    large: bool = false,
};

fn setSectionType(sh: *elf.Elf64_Shdr, sh_type: elf.Word) void {
    // If the section type is changed from SHT_NOBITS,
    // then the offset might become misaligned.
    if (sh.sh_type == elf.SHT_NOBITS and sh_type != elf.SHT_NOBITS)
        sh.sh_offset = std.mem.alignForward(
            elf.Elf64_Off,
            sh.sh_offset,
            @max(sh.sh_addralign, 1),
        );
    sh.sh_type = sh_type;
}

fn setSectionFlags(sh: *elf.Elf64_Shdr, flags: SectionFlags, is_x86_64: bool) void {
    // For ELF objects, the flags have the following effects:
    //     alloc = add the SHF_ALLOC flag.
    //     load = if the section has SHT_NOBITS type, mark it as a SHT_PROGBITS section.
    //     readonly = if this flag is not specified, add the SHF_WRITE flag.
    //     exclude = add the SHF_EXCLUDE flag.
    //     code = add the SHF_EXECINSTR flag.
    //     merge = add the SHF_MERGE flag.
    //     strings = add the SHF_STRINGS flag.
    //     contents = if the section has SHT_NOBITS type, mark it as a SHT_PROGBITS section.
    //     large = add the SHF_X86_64_LARGE on x86_64; rejected if the target architecture is not x86_64.
    var new_flags: elf.Elf64_Xword = 0;
    if (flags.alloc) new_flags |= elf.SHF_ALLOC;
    if (!flags.readonly) new_flags |= elf.SHF_WRITE;
    if (flags.code) new_flags |= elf.SHF_EXECINSTR;
    if (flags.merge) new_flags |= elf.SHF_MERGE;
    if (flags.strings) new_flags |= elf.SHF_STRINGS;
    if (flags.exclude) new_flags |= elf.SHF_EXCLUDE;
    if (flags.large) {
        if (!is_x86_64) fatal(
            "zig objcopy: 'large' section flag is only supported on x86_64 targets",
            .{},
        );
        new_flags |= elf.SHF_X86_64_LARGE;
    }

    // LLVM preserves some flags when applying the new ones, including os/arch specific flags.
    const preserve_mask: elf.Elf64_Xword =
        (elf.SHF_INFO_LINK | elf.SHF_LINK_ORDER | elf.SHF_GROUP |
            elf.SHF_TLS | elf.SHF_COMPRESSED | elf.SHF_MASKOS |
            elf.SHF_MASKPROC)
        // exclude and large overlap with some preserved flags and need to be masked out
        & ~(elf.SHF_EXCLUDE | @as(elf.Elf64_Xword, if (is_x86_64) elf.SHF_X86_64_LARGE else 0));

    sh.sh_flags = (sh.sh_flags & preserve_mask) | (new_flags & ~preserve_mask);

    if (sh.sh_type == elf.SHT_NOBITS and (flags.load or flags.contents or
        // LLVM also promotes non-ALLOC NOBITS sections since they're nonsensical.
        sh.sh_flags & elf.SHF_ALLOC == 0))
    {
        setSectionType(sh, elf.SHT_PROGBITS);
    }
}

const DumpSection = struct {
    section: *const elf.Elf64_Shdr,
    string_table: []const u8,

    pub fn format(d: DumpSection, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const sh_name: []const u8 = if (d.section.sh_name != 0)
            std.mem.sliceTo(d.string_table[d.section.sh_name..], 0)
        else
            "";

        const sh_type = switch (d.section.sh_type) {
            elf.SHT_NULL => "NULL",
            elf.SHT_PROGBITS => "PROGBITS",
            elf.SHT_SYMTAB => "SYMTAB",
            elf.SHT_STRTAB => "STRTAB",
            elf.SHT_RELA => "RELA",
            elf.SHT_HASH => "HASH",
            elf.SHT_DYNAMIC => "DYNAMIC",
            elf.SHT_NOTE => "NOTE",
            elf.SHT_NOBITS => "NOBITS",
            elf.SHT_REL => "REL",
            elf.SHT_SHLIB => "SHLIB",
            elf.SHT_DYNSYM => "DYNSYM",
            elf.SHT_INIT_ARRAY => "INIT_ARRAY",
            elf.SHT_FINI_ARRAY => "FINI_ARRAY",
            elf.SHT_PREINIT_ARRAY => "PREINIT_ARRAY",
            elf.SHT_GROUP => "GROUP",
            elf.SHT_SYMTAB_SHNDX => "SYMTAB_SHNDX",
            elf.SHT_LOOS => "LOOS",
            elf.SHT_LLVM_ADDRSIG => "LLVM_ADDRSIG",
            elf.SHT_GNU_HASH => "GNU_HASH",
            elf.SHT_GNU_VERDEF => "GNU_VERDEF",
            elf.SHT_GNU_VERNEED => "GNU_VERNEED",
            elf.SHT_GNU_VERSYM => "GNU_VERSYM/SHT_HIOS",
            // elf.SHT_HIOS => "HIOS",
            elf.SHT_LOPROC => "LOPROC",
            elf.SHT_X86_64_UNWIND => "X86_64_UNWIND",
            elf.SHT_HIPROC => "HIPROC",
            elf.SHT_LOUSER => "LOUSER",
            elf.SHT_HIUSER => "HIUSER",
            else => "unknown",
        };

        try writer.print("name: {s: <20}, type: {s: <13}, ", .{ sh_name, sh_type });
        {
            try writer.writeAll("flags: ");
            var written: u8 = 0;
            inline for ([_]elf.Elf64_Xword{
                elf.SHF_WRITE,      elf.SHF_ALLOC,
                elf.SHF_EXECINSTR,  elf.SHF_MERGE,
                elf.SHF_STRINGS,    elf.SHF_INFO_LINK,
                elf.SHF_LINK_ORDER, elf.SHF_OS_NONCONFORMING,
                elf.SHF_GROUP,      elf.SHF_TLS,
                elf.SHF_COMPRESSED, elf.SHF_MASKOS,
                elf.SHF_MASKPROC,   elf.SHF_EXCLUDE,
            }, [_][]const u8{
                "WRITE",      "ALLOC",
                "EXEC",       "MERGE",
                "STRINGS",    "INFO_LINK",
                "LINK_ORDER", "OS_NONCONFORMING",
                "GROUP",      "TLS",
                "COMPRESSED", "MASKOS",
                "MASKPROC",   "EXCLUDE",
            }) |flag, name| {
                if (d.section.sh_flags & flag > 0) {
                    if (written > 0) {
                        try writer.writeByte('|');
                        written += 1;
                    }
                    try writer.writeAll(name);
                    written += name.len;
                }
            }
            if (written == 0 and d.section.sh_flags > 0) {
                var counter: std.Io.Writer.Discarding = .init(&.{});
                counter.writer.print("0x{x}", .{d.section.sh_flags}) catch unreachable;
                try writer.print("0x{x}", .{d.section.sh_flags});
                written += @intCast(counter.count);
            }
            try writer.splatByteAll(' ', 15 -| written);
            try writer.writeAll(", ");
        }

        try writer.print("addr: 0x{x: <6}, offset: 0x{x: <6}, size: {d: <8}, " ++
            "link: {d: <4}, info: {d: <4}, addralign: {d: <4}, entsize: {d}", .{
            d.section.sh_addr,
            d.section.sh_offset,
            d.section.sh_size,
            d.section.sh_link,
            d.section.sh_info,
            d.section.sh_addralign,
            d.section.sh_entsize,
        });
    }
};
