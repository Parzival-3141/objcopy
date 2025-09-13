const std = @import("std");
const builtin = @import("builtin");
const elf = std.elf;

const fatal = std.process.fatal;

const help =
    \\Usage: zig objcopy [options] input output
    \\
    \\Options:
    \\  -h, --help                              Print this help and exit.
    \\  -O, --output-target <format>            Write the output as the specified format. If unspecified, the output format is assumed to be the same as the input file’s format.
    \\  --add-section <section>=<file>          Add a section named <section> with the contents of <file> to the output. Can be specified multiple times to add multiple sections.
    \\  --set-section-flags <section>=<flags>   Set flags of <section> to <flags>, represented as a comma separated list. Can be specified multiple times to update multiple sections.
;

pub fn main() !void {
    var arena_inst: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var args = try std.process.argsWithAllocator(arena);
    _ = args.skip();

    var opt_output_target: ?ObjectFormat = null;
    var opt_add_sections: std.ArrayList(AddSection) = .empty;
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
                else if (strEql(opt, "hex") or strEql(opt, "ihex"))
                    .hex
                else
                    fatal("unrecognized object format: {s}", .{opt});
        } else if (std.mem.eql(u8, arg, "--add-section")) {
            const opt = args.next() orelse fatal("expected another argument after '{s}'", .{arg});
            const split = splitOption(opt) orelse fatal("unrecognized argument: '{s}', expected <section>=<file>", .{opt});
            try opt_add_sections.append(arena, .{ .section_name = split.first, .file_path = split.second });
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

    // @Incomplete detect/accept input object format
    const input_ofmt: ObjectFormat = .elf;
    const output_ofmt = opt_output_target orelse input_ofmt;

    // @Todo Should we read the entire file into memory or seek & read as needed?
    const input_file = std.fs.cwd().openFile(input, .{}) catch |err|
        fatal("failed to open {s}: {t}", .{ input, err });
    defer input_file.close();

    const output_file = try std.fs.cwd().createFile(output, .{});
    defer output_file.close();

    var input_buffer: [4096]u8 = undefined;
    var input_reader = input_file.reader(&input_buffer);

    var elf_obj = try ElfObj.read(arena, &input_reader);
    std.debug.print("{}\n", .{elf_obj.header});

    for (opt_add_sections.items) |add| {
        // @Incomplete check if section already exists?
        // @Incomplete error handling

        // @Todo maybe save file path/handle and only write/copy when necessary?
        const add_file = try std.fs.cwd().openFile(add.file_path, .{});
        errdefer add_file.close();
        const stat = try add_file.stat();

        const new_sect: *ElfObj.Section = try elf_obj.sections.addOne(arena);
        try elf_obj.sh_string_table.ensureUnusedCapacity(arena, add.section_name.len + 1);

        const name_idx = elf_obj.sh_string_table.items.len;
        elf_obj.sh_string_table.appendSliceAssumeCapacity(add.section_name);
        elf_obj.sh_string_table.appendAssumeCapacity(0);
        // @Incomplete @Bug don't assume shstrtab existed in input object. May need to be handled in other places as well
        elf_obj.sections.items[elf_obj.header.shstrndx].hdr.sh_size += add.section_name.len + 1;

        const sect_type: elf.Word = if (std.mem.startsWith(u8, add.section_name, ".note"))
            elf.SHT_NOTE
        else
            elf.SHT_PROGBITS;

        new_sect.* = .{
            .hdr = .{
                .sh_name = @intCast(name_idx),
                .sh_type = sect_type,
                .sh_flags = 0,
                .sh_addr = 0,
                .sh_offset = ElfObj.Section.null_offset,
                .sh_size = stat.size,
                .sh_link = elf.SHN_UNDEF,
                .sh_info = elf.SHN_UNDEF,
                .sh_addralign = 1,
                .sh_entsize = 0,
            },
            .payload = .{ .file = add_file },
        };
        elf_obj.header.shnum += 1;
    }

    const string_table = elf_obj.sh_string_table.items;

    for (elf_obj.sections.items) |*section| {
        const sh_name = getSectionName(string_table, section.hdr.sh_name);

        for (opt_set_section_flags.items) |set_flags| {
            if (strEql(set_flags.section_name, sh_name)) {
                ElfObj.setSectionFlags(&section.hdr, set_flags.flags, elf_obj.header.machine == .X86_64);
            }
        }
    }

    try elf_obj.computeFinalLayout();
    for (elf_obj.sections.items) |section| std.debug.print("{f}\n", .{
        ElfObj.DumpSection{ .section = &section.hdr, .string_table = string_table },
    });

    var out_buffer: [4096]u8 = undefined;
    var out_writer = output_file.writer(&out_buffer);
    try elf_obj.write(&input_reader, &out_writer, output_ofmt);
    try out_writer.end();
}

fn getSectionName(shstrtab: []const u8, off: u32) [:0]const u8 {
    const slice = shstrtab[off..];
    return slice[0..std.mem.indexOfScalar(u8, slice, 0).? :0];
}

const ObjectFormat = enum {
    coff,
    elf,
    hex,
    /// "raw" executable image
    raw,
};

const AddSection = struct {
    section_name: []const u8,
    file_path: []const u8,
};
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

/// Deserialized ELF file. 32/64bit and endian agnostic.
const ElfObj = struct {
    header: elf.Header,

    // Stored in native-endian format, depending on target endianness needs to be bswapped on read/write.
    // Same order as in the file.
    phdr_table: []elf.Elf64_Phdr,
    sections: std.ArrayList(Section),

    /// .shstrtab buffer
    sh_string_table: std.ArrayList(u8),

    pub fn read(allocator: std.mem.Allocator, file_reader: *std.fs.File.Reader) !ElfObj {
        const header = try elf.Header.read(&file_reader.interface);

        const phdrs = try allocator.alloc(elf.Elf64_Phdr, header.phnum);
        errdefer allocator.free(phdrs);
        const sections = try allocator.alloc(Section, header.shnum);
        errdefer allocator.free(sections);

        var i: usize = 0;
        var ph_iter = header.iterateProgramHeaders(file_reader);
        while (try ph_iter.next()) |ph| : (i += 1) phdrs[i] = ph;
        std.debug.assert(i == header.phnum);

        i = 0;
        var sh_iter = header.iterateSectionHeaders(file_reader);
        while (try sh_iter.next()) |sh| : (i += 1) {
            sections[i] = .{
                .hdr = sh,
                .original_offset = sh.sh_offset,
            };
        }
        std.debug.assert(i == header.shnum);

        var shstrtab: std.ArrayList(u8) = .empty; // @Todo initialize with &.{0}
        if (header.shstrndx != elf.SHN_UNDEF) {
            try file_reader.seekTo(sections[header.shstrndx].hdr.sh_offset);
            const size = sections[header.shstrndx].hdr.sh_size;
            var w: std.Io.Writer.Allocating = try .initCapacity(allocator, size);
            errdefer w.deinit();

            try file_reader.interface.streamExact(&w.writer, size);
            shstrtab = w.toArrayList();
        }

        return .{
            .header = header,
            .phdr_table = phdrs,
            .sections = .fromOwnedSlice(sections),
            .sh_string_table = shstrtab,
        };
    }

    pub fn computeFinalLayout(obj: *ElfObj) !void {
        // set shstrtab to use the updated string contents
        obj.sections.items[obj.header.shstrndx].payload = .{
            .bytes = obj.sh_string_table.items,
        };

        var offset: usize = 0;

        offset += if (obj.header.is_64)
            @sizeOf(elf.Elf64_Ehdr)
        else
            @sizeOf(elf.Elf32_Ehdr);

        obj.header.phoff = if (obj.phdr_table.len > 0) offset else 0;
        offset += obj.header.phentsize * obj.phdr_table.len;

        // Whether the section table comes before or after the contents is largely arbitrary,
        // but most educational materials show the table at the end.
        for (obj.sections.items) |*section| {
            const alignment: std.mem.Alignment = .fromByteUnits(@max(1, section.hdr.sh_addralign));
            offset = alignment.forward(offset);
            section.hdr.sh_offset = offset;

            offset += size: {
                if (section.payload) |payload| switch (payload) {
                    .file => |file| {
                        const stat = try file.stat(); // @Todo cache this when adding the section? Would make this fn unable to fail.
                        break :size stat.size;
                    },
                    .bytes => |b| {
                        break :size b.len;
                    },
                } else {
                    break :size section.hdr.sh_size;
                }
            };
        }

        obj.header.shoff = if (obj.sections.items.len > 0) offset else 0;
        offset += obj.header.shentsize * obj.sections.items.len;
    }

    pub fn write(
        obj: ElfObj,
        input: *std.fs.File.Reader,
        output: *std.fs.File.Writer,
        ofmt: ObjectFormat,
    ) !void {
        _ = ofmt; // @Incomplete

        switch (obj.header.is_64) {
            inline else => |is_64| {
                var ident_buf: [elf.EI_NIDENT]u8 = @splat(0);
                ident_buf[0..4].* = elf.MAGIC.*;
                ident_buf[elf.EI_CLASS] = if (is_64) elf.ELFCLASS64 else elf.ELFCLASS32;
                ident_buf[elf.EI_DATA] = switch (obj.header.endian) {
                    .little => elf.ELFDATA2LSB,
                    .big => elf.ELFDATA2MSB,
                };
                ident_buf[elf.EI_VERSION] = 1;
                ident_buf[elf.EI_OSABI] = @intFromEnum(obj.header.os_abi);
                ident_buf[elf.EI_ABIVERSION] = obj.header.abi_version;

                const Ehdr = if (is_64) elf.Elf64_Ehdr else elf.Elf32_Ehdr;
                const ehdr: Ehdr = .{
                    .e_ident = ident_buf,
                    .e_type = obj.header.type,
                    .e_machine = obj.header.machine,
                    .e_version = 1,
                    .e_entry = @intCast(obj.header.entry),
                    .e_phoff = @intCast(obj.header.phoff),
                    .e_shoff = @intCast(obj.header.shoff),
                    .e_flags = 0, // @Incomplete
                    .e_ehsize = @sizeOf(Ehdr),
                    .e_phentsize = obj.header.phentsize,
                    .e_phnum = obj.header.phnum,
                    .e_shentsize = obj.header.shentsize,
                    .e_shnum = obj.header.shnum,
                    .e_shstrndx = obj.header.shstrndx,
                };
                try output.interface.writeStruct(ehdr, obj.header.endian);

                for (obj.phdr_table) |phdr| {
                    const tgt_phdr: if (is_64) elf.Elf64_Phdr else elf.Elf32_Phdr = .{
                        .p_type = phdr.p_type,
                        .p_offset = @intCast(phdr.p_offset),
                        .p_vaddr = @intCast(phdr.p_vaddr),
                        .p_paddr = @intCast(phdr.p_paddr),
                        .p_filesz = @intCast(phdr.p_filesz),
                        .p_memsz = @intCast(phdr.p_memsz),
                        .p_flags = phdr.p_flags,
                        .p_align = @intCast(phdr.p_align),
                    };
                    try output.interface.writeStruct(tgt_phdr, obj.header.endian);
                }

                for (obj.sections.items) |section| {
                    try output.interface.flush();
                    try output.seekTo(section.hdr.sh_offset);

                    if (section.payload) |payload| switch (payload) {
                        .file => |file| {
                            defer file.close();
                            var buf: [1024]u8 = undefined; // @Performance does this need a buffer?
                            var file_reader = file.reader(&buf);
                            _ = try output.interface.sendFileAll(&file_reader, .unlimited);
                        },
                        .bytes => |b| {
                            try output.interface.writeAll(b);
                        },
                    } else {
                        // pull unmodified data from input
                        std.debug.assert(section.original_offset != Section.null_offset);
                        try input.seekTo(section.original_offset);
                        _ = try output.interface.sendFileAll(input, .limited64(section.hdr.sh_size));
                    }
                }

                for (obj.sections.items) |section| {
                    const shdr: if (is_64) elf.Elf64_Shdr else elf.Elf32_Shdr = .{
                        .sh_name = section.hdr.sh_name,
                        .sh_type = section.hdr.sh_type,
                        .sh_flags = @intCast(section.hdr.sh_flags),
                        .sh_addr = @intCast(section.hdr.sh_addr),
                        .sh_offset = @intCast(section.hdr.sh_offset),
                        .sh_size = @intCast(section.hdr.sh_size),
                        .sh_link = section.hdr.sh_link,
                        .sh_info = section.hdr.sh_info,
                        .sh_addralign = @intCast(section.hdr.sh_addralign),
                        .sh_entsize = @intCast(section.hdr.sh_entsize),
                    };
                    try output.interface.writeStruct(shdr, obj.header.endian);
                }
            },
        }
    }

    const Section = struct {
        hdr: elf.Elf64_Shdr,

        /// Data that will be added with this section.
        payload: ?Payload = null,

        original_offset: elf.Elf64_Off = null_offset,

        const null_offset = std.math.maxInt(elf.Elf64_Off);

        const Payload = union(enum) {
            file: std.fs.File,
            bytes: []u8,
        };
    };

    pub fn setSectionType(sh: *elf.Elf64_Shdr, sh_type: elf.Word) void {
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

    pub fn setSectionFlags(sh: *elf.Elf64_Shdr, flags: SectionFlags, is_x86_64: bool) void {
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

    pub const DumpSection = struct {
        section: *const elf.Elf64_Shdr,
        string_table: []const u8,

        pub fn format(d: DumpSection, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const sh_name = getSectionName(d.string_table, d.section.sh_name);

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
};

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
    try std.testing.expectEqual(null, splitOption("abc=")); // @Todo this case shouldn't return null
    try std.testing.expectEqual(null, splitOption("=abc"));
}

fn strEql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
