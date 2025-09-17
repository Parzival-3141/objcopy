const std = @import("std");
const builtin = @import("builtin");
const elf = std.elf;

const fatal = std.process.fatal;

const help =
    \\Usage: zig objcopy [options] <input> <output>
    \\
    \\Options:
    \\  -h, --help                              Print this help and exit.
    \\  -O, --output-target <format>            Write the output as the specified format. If unspecified, the output format is assumed to be the same as the input file’s format.
    \\  --add-section <section>=<file>          Add a section named <section> with the contents of <file> to the output. Can be specified multiple times to add multiple sections.
    \\  -R, --remove-section <section>          Remove the specified section from the output. Can be specified multiple times to remove multiple sections simultaneously.
    \\  --set-section-flags <section>=<flags>   Set flags of <section> to <flags>, represented as a comma separated list. Can be specified multiple times to update multiple sections.
;

pub fn main() !void {
    var arena_inst: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var args = try std.process.argsWithAllocator(arena);
    _ = args.skip();

    // @Incomplete deduplicate add/remove/set flags
    var opt_output_target: ?ObjectFormat = null;
    var opt_add_sections: std.ArrayList(AddSection) = .empty;
    var opt_remove_sections: std.ArrayList([]const u8) = .empty;
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
        } else if (strEql(arg, "-h") or strEql(arg, "--help")) {
            return std.debug.print("{s}\n", .{help}); // @Todo print to stdout
        } else if (strEql(arg, "-O") or strEql(arg, "--output-target")) {
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
        } else if (strEql(arg, "--add-section")) {
            const opt = args.next() orelse fatal("expected another argument after '{s}'", .{arg});
            const split = splitOption(opt) orelse fatal("unrecognized argument: '{s}', expected <section>=<file>", .{opt});
            try opt_add_sections.append(arena, .{ .section_name = split.first, .file_path = split.second });
        } else if (strEql(arg, "-R") or strEql(arg, "--remove-section")) {
            const opt = args.next() orelse fatal("expected another argument after '{s}'", .{arg});
            try opt_remove_sections.append(arena, opt);
        } else if (strEql(arg, "--set-section-flags")) {
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

    const string_table = &elf_obj.shstrtab_buffer.items;

    // Remove sections and any dead references:
    // create list of sections that should be removed
    // remove sections from segments
    // run section on-removal code depending on section type (only used by group sections to remove child members)
    // remove references to dead sections in alive ones (meat and potatoes)

    elf_obj.removed_sections = blk: {
        var to_remove: std.SinglyLinkedList = .{};
        // the first node is always the null section, so we can safely ignore it in removal checks
        var node = elf_obj.sections.first;
        while (node) |n| {
            const section: *ElfObj.Section = @fieldParentPtr("node", n.next orelse break);
            for (opt_remove_sections.items) |rm_name| {
                if (strEql(section.name(string_table.*), rm_name)) {
                    // @Incomplete remove from segment list
                    if (section.sh_type & elf.SHT_GROUP > 0) {
                        // @Incomplete remove SHF_GROUP flag from group members
                    }
                    to_remove.prepend(n.removeNext().?);
                    break;
                }
            } else {
                node = n.next;
            }
        }
        break :blk to_remove;
    };

    var it = elf_obj.iterateSections();
    while (it.next()) |alive_section| {
        // remove references to dead sections depending on the alive section's type
        switch (alive_section.sh_type) {
            elf.SHT_SYMTAB => {
                std.log.warn("@Incomplete: remove references to dead sections in SHT_SYMTAB", .{});
                // sh_link == The section header index of the associated string table.
                // sh_info == One greater than the symbol table index of the last local symbol (binding STB_LOCAL).

                if (alive_section.sh_link) |link| {
                    if (linkedListContains(elf_obj.removed_sections, &link.node)) {
                        fatal(
                            "string table '{s}' cannot be removed because it's referenced by symbol table '{s}'",
                            .{ link.name(string_table.*), alive_section.name(string_table.*) },
                        );
                    }
                }

                // @Incomplete remove symbols that reference dead sections
            },
            elf.SHT_GROUP => {
                // sh_link == The section header index of the associated symbol table.
                // sh_info == The symbol table index of an entry in the associated symbol table. The name of the specified symbol table entry provides a signature for the section group.

                std.log.warn("@Incomplete: remove references to dead sections in SHT_GROUP", .{});
            },
            elf.SHT_REL, elf.SHT_RELA => {
                std.log.warn("@Incomplete: remove references to dead sections in SHT_REL(A)", .{});
            },
            else => {
                if (alive_section.sh_link) |link| {
                    if (linkedListContains(elf_obj.removed_sections, &link.node)) {
                        fatal(
                            "section '{s}' cannot be removed because it's referenced by section '{s}'",
                            .{ link.name(string_table.*), alive_section.name(string_table.*) },
                        );
                    }
                }
            },
        }
    }

    // Add sections
    for (opt_add_sections.items) |add| {
        // @Incomplete check if section already exists?
        // @Incomplete error handling

        // @Todo maybe save file path/handle and only write/copy when necessary?
        const add_file = try std.fs.cwd().openFile(add.file_path, .{});
        errdefer add_file.close();
        const stat = try add_file.stat();

        const new_sect: *ElfObj.Section = try arena.create(ElfObj.Section);
        const name_idx = try elf_obj.insertShString(arena, add.section_name);

        const sect_type: elf.Word = if (std.mem.startsWith(u8, add.section_name, ".note"))
            elf.SHT_NOTE
        else
            elf.SHT_PROGBITS;

        new_sect.* = .{
            .node = .{},
            .sh_name = name_idx,
            .sh_type = sect_type,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_offset = ElfObj.Section.null_offset,
            .sh_size = stat.size,
            .sh_link = null,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
            .payload = .{ .file = add_file },
        };
        if (elf_obj.sections.first) |first| {
            first.findLast().insertAfter(&new_sect.node);
        } else elf_obj.sections.prepend(&new_sect.node);
    }

    // Set section flags
    // @Todo fail on no matches?
    it.reset(elf_obj);
    while (it.next()) |section| {
        const sh_name = section.name(string_table.*);
        for (opt_set_section_flags.items) |set_flags| {
            if (strEql(set_flags.section_name, sh_name)) {
                ElfObj.setSectionFlags(section, set_flags.flags, elf_obj.header.machine == .X86_64);
            }
        }
    }

    try elf_obj.computeFinalLayout();

    var i: usize = 0;
    it.reset(elf_obj);
    while (it.next()) |section| : (i += 1) {
        std.debug.print("{f}\n", .{
            ElfObj.DumpSection{ .idx = i, .section = section, .string_table = string_table.* },
        });
    }

    var out_buffer: [4096]u8 = undefined;
    var out_writer = output_file.writer(&out_buffer);
    try elf_obj.write(&input_reader, &out_writer, output_ofmt);
    try out_writer.end();
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

    // Updating section indices while modifying the data is annoying, so section references are stored as pointers instead.
    // Sections are stored in a linked list to preserve insertion order without invalidating pointers.
    sections: std.SinglyLinkedList,

    shstrtab: *Section,
    shstrtab_buffer: std.ArrayList(u8),

    removed_sections: std.SinglyLinkedList,

    pub fn read(allocator: std.mem.Allocator, file_reader: *std.fs.File.Reader) !ElfObj {
        const header = try elf.Header.read(&file_reader.interface);

        // @Todo can we work around this? Are there use cases for running objcopy on files without a shstrtab?
        if (header.shstrndx == elf.SHN_UNDEF)
            fatal("missing section .shstrtab: zig objcopy requires the section name string table in order to run", .{});

        var shstrtab: *Section = undefined;

        const phdrs = try allocator.alloc(elf.Elf64_Phdr, header.phnum);
        errdefer allocator.free(phdrs);
        const sections = try allocator.alloc(Section, header.shnum);
        errdefer allocator.free(sections);

        var i: usize = 0;
        var ph_iter = header.iterateProgramHeaders(file_reader);
        while (try ph_iter.next()) |ph| : (i += 1) phdrs[i] = ph;
        std.debug.assert(i == header.phnum);

        i = 0;
        var section_list: std.SinglyLinkedList = .{};
        var prev_node: ?*std.SinglyLinkedList.Node = null;
        var sh_iter = header.iterateSectionHeaders(file_reader);
        while (try sh_iter.next()) |sh| : (i += 1) {
            sections[i] = .{
                .node = .{},
                .sh_name = sh.sh_name,
                .sh_type = sh.sh_type,
                .sh_flags = sh.sh_flags,
                .sh_addr = sh.sh_addr,
                .sh_offset = sh.sh_offset,
                .sh_size = sh.sh_size,
                .sh_link = if (sh.sh_link != elf.SHN_UNDEF) &sections[sh.sh_link] else null,
                .sh_info = sh.sh_info,
                .sh_addralign = sh.sh_addralign,
                .sh_entsize = sh.sh_entsize,
                .original_offset = sh.sh_offset,
            };
            if (header.shstrndx == i)
                shstrtab = &sections[i];

            // append to last node orelse set first
            if (prev_node) |n| {
                n.insertAfter(&sections[i].node);
            } else {
                section_list.prepend(&sections[i].node);
            }
            prev_node = &sections[i].node;
        }
        std.debug.assert(i == header.shnum);

        var shstrtab_buf: std.ArrayList(u8) = .empty; // @Todo if running without an existing shstrtab is ever supported, this needs to be initialized to `&.{0}`.
        {
            try file_reader.seekTo(shstrtab.original_offset);
            const size = shstrtab.sh_size;
            var w: std.Io.Writer.Allocating = try .initCapacity(allocator, size);
            errdefer w.deinit();

            try file_reader.interface.streamExact(&w.writer, size);
            shstrtab_buf = w.toArrayList();
        }

        return .{
            .header = header,
            .phdr_table = phdrs,
            .sections = section_list,
            .shstrtab = shstrtab,
            .shstrtab_buffer = shstrtab_buf,
            .removed_sections = .{},
        };
    }

    pub fn computeFinalLayout(obj: *ElfObj) !void {
        obj.header.phnum = @intCast(obj.phdr_table.len);
        obj.header.shnum = @intCast(obj.sections.len());

        // set shstrtab to use the updated string contents
        obj.shstrtab.payload = .{
            .bytes = obj.shstrtab_buffer.items,
        };

        var offset: usize = 0;

        offset += if (obj.header.is_64)
            @sizeOf(elf.Elf64_Ehdr)
        else
            @sizeOf(elf.Elf32_Ehdr);

        obj.header.phoff = if (obj.header.phnum > 0) offset else 0;
        offset += obj.header.phentsize * obj.header.phnum;

        // Whether the section table comes before or after the contents is largely arbitrary,
        // but most educational materials show the table at the end.
        var i: elf.Word = 0;
        var it = obj.iterateSections();
        while (it.next()) |section| : (i += 1) {
            const alignment: std.mem.Alignment = .fromByteUnits(@max(1, section.sh_addralign));
            offset = alignment.forward(offset);
            section.sh_offset = offset;
            section.final_index = i;

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
                    break :size section.sh_size;
                }
            };
        }

        obj.header.shoff = if (obj.header.shnum > 0) offset else 0;
        offset += obj.header.shentsize * obj.header.shnum;
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

                var it = obj.iterateSections();
                while (it.next()) |section| {
                    try output.interface.flush();
                    try output.seekTo(section.sh_offset);

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
                        _ = try output.interface.sendFileAll(input, .limited64(section.sh_size));
                    }
                }

                it.reset(obj);
                while (it.next()) |section| {
                    const shdr: if (is_64) elf.Elf64_Shdr else elf.Elf32_Shdr = .{
                        .sh_name = section.sh_name,
                        .sh_type = section.sh_type,
                        .sh_flags = @intCast(section.sh_flags),
                        .sh_addr = @intCast(section.sh_addr),
                        .sh_offset = @intCast(section.sh_offset),
                        .sh_size = @intCast(section.sh_size),
                        .sh_link = if (section.sh_link) |link| link.final_index else elf.SHN_UNDEF,
                        .sh_info = section.sh_info,
                        .sh_addralign = @intCast(section.sh_addralign),
                        .sh_entsize = @intCast(section.sh_entsize),
                    };
                    try output.interface.writeStruct(shdr, obj.header.endian);
                }
            },
        }
    }

    pub fn iterateSections(obj: ElfObj) SectionIterator {
        return .{ .node = obj.sections.first };
    }
    const SectionIterator = struct {
        node: ?*std.SinglyLinkedList.Node,

        pub fn next(it: *SectionIterator) ?*Section {
            const n = it.node orelse return null;
            it.node = n.next;
            return @fieldParentPtr("node", n);
        }

        pub fn reset(it: *SectionIterator, obj: ElfObj) void {
            it.node = obj.sections.first;
        }
    };

    fn insertShString(
        obj: *ElfObj,
        // @Todo ElfObj should probably have it's own allocator
        allocator: std.mem.Allocator,
        str: []const u8,
    ) !u32 {
        try obj.shstrtab_buffer.ensureUnusedCapacity(allocator, str.len + 1);
        obj.shstrtab.sh_size += str.len + 1;

        const str_idx: u32 = @intCast(obj.shstrtab_buffer.items.len);
        obj.shstrtab_buffer.appendSliceAssumeCapacity(str);
        obj.shstrtab_buffer.appendAssumeCapacity(0);
        return str_idx;
    }

    fn getSectionName(obj: ElfObj, s: Section) [:0]const u8 {
        return getStrTabEntry(obj.shstrtab_buffer.items, s.sh_name);
    }

    fn getStrTabEntry(strtab: []const u8, off: u32) [:0]const u8 {
        const slice = strtab[off..];
        return slice[0..std.mem.indexOfScalar(u8, slice, 0).? :0];
    }

    const Section = struct {
        node: std.SinglyLinkedList.Node,

        sh_name: elf.Word,
        sh_type: elf.Word,
        sh_flags: elf.Elf64_Xword,
        sh_addr: elf.Elf64_Addr,
        sh_offset: elf.Elf64_Off,
        sh_size: elf.Elf64_Xword,

        // sh_link: elf.Word,
        sh_link: ?*Section, // @Incomplete cannot represent special section indexes
        sh_info: elf.Word,

        sh_addralign: elf.Elf64_Xword,
        sh_entsize: elf.Elf64_Xword,

        /// Data that will be added with this section.
        payload: ?Payload = null,

        /// Used to convert a section reference to an index.
        /// Only valid after calling `ElfObj.computeFinalLayout()`.
        final_index: elf.Word = elf.SHN_UNDEF,

        /// Original `sh_offset` field. Used for reading data from the input file.
        /// Sections that don't originate from the input should use the `null_offset` value.
        original_offset: elf.Elf64_Off = null_offset,

        const null_offset = std.math.maxInt(elf.Elf64_Off);

        const Payload = union(enum) {
            file: std.fs.File,
            bytes: []u8,
        };

        fn name(s: Section, shstrtab: []const u8) [:0]const u8 {
            return getStrTabEntry(shstrtab, s.sh_name);
        }
    };

    pub fn setSectionType(sh: *Section, sh_type: elf.Word) void {
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

    pub fn setSectionFlags(sh: *Section, flags: SectionFlags, is_x86_64: bool) void {
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
        idx: usize,
        section: *const Section,
        string_table: []const u8,

        pub fn format(d: DumpSection, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            const sh_name = getStrTabEntry(d.string_table, d.section.sh_name);

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
                elf.SHT_LLVM_ADDRSIG => "LLVM_ADDRSIG",
                elf.SHT_GNU_HASH => "GNU_HASH",
                elf.SHT_GNU_VERDEF => "GNU_VERDEF",
                elf.SHT_GNU_VERNEED => "GNU_VERNEED",
                elf.SHT_GNU_VERSYM => "GNU_VERSYM",
                elf.SHT_X86_64_UNWIND => "X86_64_UNWIND",
                else => |sh_type| switch (sh_type) {
                    elf.SHT_LOOS...elf.SHT_HIOS => "OS_unknown",
                    elf.SHT_LOPROC...elf.SHT_HIPROC => "PROC_unknown",
                    elf.SHT_LOUSER...elf.SHT_HIUSER => "USER_unknown",
                    else => "unknown",
                },
            };

            try writer.print("[{d: >2}] name: {s: <20}, type: {s: <13}, ", .{ d.idx, sh_name, sh_type });
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
                if (d.section.sh_link) |link| link.final_index else elf.SHN_UNDEF,
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

// @Todo @Performance use of this function probably means you're using the wrong data structure
fn linkedListContains(
    list: std.SinglyLinkedList,
    needle: *const std.SinglyLinkedList.Node,
) bool {
    var it = list.first;
    return while (it) |node| : (it = node.next) {
        if (node == needle) break true;
    } else false;
}
