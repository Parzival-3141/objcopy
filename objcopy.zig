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

    const input_file = std.fs.cwd().openFile(input, .{}) catch |err|
        fatal("failed to open {s}: {t}", .{ input, err });
    defer input_file.close();

    const output_file = try std.fs.cwd().createFile(output, .{});
    defer output_file.close();

    var input_buffer: [4096]u8 = undefined;
    var input_reader = input_file.reader(&input_buffer);

    var elf_obj = try ElfObj.read(arena, &input_reader);
    std.debug.print("{}\n", .{elf_obj.header});

    // Remove sections and any dead references:
    // create list of sections that should be removed
    // remove sections from segments
    // run section on-removal code depending on section type (only used by group sections to remove child members)
    // remove references to dead sections in alive ones (meat and potatoes)
    {
        var i: usize = 0;
        while (i < elf_obj.shdr_table.items.len) {
            const section = elf_obj.shdr_table.items[i].get(elf_obj);
            for (opt_remove_sections.items) |rm_name| {
                if (strEql(section.name(elf_obj), rm_name)) {
                    // @Incomplete remove from segment list

                    if (section.sh_type == elf.SHT_GROUP) {
                        // remove SHF_GROUP flag from group members
                        for (section.contents.group.sections.items) |member_ref| {
                            member_ref.get(elf_obj).sh_flags &= ~@as(elf.Elf64_Xword, elf.SHF_GROUP);
                        }
                    }

                    try elf_obj.removed_sections.append(arena, elf_obj.shdr_table.orderedRemove(i));
                    break;
                }
            } else i += 1;
        }
    }

    if (elf_obj.removed_sections.items.len > 0) for (elf_obj.shdr_table.items) |alive_ref| {
        const alive_section = alive_ref.get(elf_obj);

        const S = struct {
            pub fn isDeadLink(link: ElfObj.Shdr.Ref, obj: ElfObj) ?*ElfObj.Shdr {
                return if (link != .undef and sliceContains(
                    ElfObj.Shdr.Ref,
                    obj.removed_sections.items,
                    link,
                )) link.get(obj) else null;
            }
        };

        // remove references to dead sections and check for dangling links in alive sections
        switch (alive_section.sh_type) {
            elf.SHT_SYMTAB => {
                // sh_link: The section header index of the associated string table.
                if (S.isDeadLink(alive_section.sh_link, elf_obj)) |dead_section| {
                    fatal(
                        "string table '{s}' cannot be removed because it's referenced by symbol table '{s}'",
                        .{ dead_section.name(elf_obj), alive_section.name(elf_obj) },
                    );
                }

                std.log.warn("@Incomplete: remove symbols that reference dead sections in SHT_SYMTAB", .{});
            },
            elf.SHT_GROUP => {
                // sh_link: The section header index of the associated symbol table.
                if (S.isDeadLink(alive_section.sh_link, elf_obj)) |dead_section| {
                    fatal(
                        "symbol table '{s}' cannot be removed because it's referenced by group section '{s}'",
                        .{ dead_section.name(elf_obj), alive_section.name(elf_obj) },
                    );
                }

                // remove dead sections from group
                const group = &alive_section.contents.group;
                var i: usize = 0;
                while (i < group.sections.items.len) {
                    if (sliceContains(
                        ElfObj.Shdr.Ref,
                        elf_obj.removed_sections.items,
                        group.sections.items[i],
                    )) {
                        _ = group.sections.swapRemove(i);
                    } else i += 1;
                }
            },
            elf.SHT_REL, elf.SHT_RELA => {
                // sh_link: The section header index of the associated symbol table.
                if (S.isDeadLink(alive_section.sh_link, elf_obj)) |dead_section| {
                    fatal(
                        "symbol table '{s}' cannot be removed because it's referenced by relocation section '{s}'",
                        .{ dead_section.name(elf_obj), alive_section.name(elf_obj) },
                    );
                }

                // sh_info: The section header index of the section to which the relocation applies.
                const reloc_target_section: ElfObj.Shdr.Ref = @enumFromInt(alive_section.sh_info);
                if (S.isDeadLink(reloc_target_section, elf_obj)) |dead_section| {
                    fatal(
                        "section '{s}' cannot be removed because it's referenced by relocation section '{s}'",
                        .{ dead_section.name(elf_obj), alive_section.name(elf_obj) },
                    );
                }

                // check relocation entries for references to dead sections
                const symtab_shdr = alive_section.sh_link.get(elf_obj);
                for (alive_section.contents.relocs.entries.items) |rel| {
                    const sym_idx = rel.r_sym();
                    if (sym_idx == 0) continue;

                    // @Incomplete this will break when symbols are added/removed.
                    const symbol = symtab_shdr.contents.symtab.symbols.items[sym_idx];
                    if (symbol.st_shndx.reserved()) continue;

                    if (S.isDeadLink(symbol.st_shndx, elf_obj)) |dead_section| {
                        const sym_name = ElfObj.getStrTabEntry(
                            symtab_shdr.sh_link.get(elf_obj).contents.strtab.items,
                            symbol.st_name,
                        );
                        fatal("section '{s}' cannot be removed: ({s}+0x{x}) has relocation against symbol '{s}'", .{
                            dead_section.name(elf_obj),
                            reloc_target_section.get(elf_obj).name(elf_obj),
                            rel.r_offset,
                            sym_name,
                        });
                    }
                }
            },
            else => {
                if (S.isDeadLink(alive_section.sh_link, elf_obj)) |dead_section| {
                    fatal(
                        "section '{s}' cannot be removed because it's referenced by section '{s}'",
                        .{ dead_section.name(elf_obj), alive_section.name(elf_obj) },
                    );
                }
            },
        }
    };

    // Add sections
    for (opt_add_sections.items) |add| {
        // @Incomplete check if section already exists?
        // @Incomplete error handling

        // @Todo maybe save file path/handle and only write/copy when necessary?
        const add_file = try std.fs.cwd().openFile(add.file_path, .{});
        errdefer add_file.close();

        try elf_obj.shdr_table.ensureUnusedCapacity(arena, 1);
        try elf_obj.shdr_buf.ensureUnusedCapacity(arena, 1);
        const name_idx = try elf_obj.insertShString(arena, add.section_name);

        const sh_type: elf.Word = if (std.mem.startsWith(u8, add.section_name, ".note"))
            elf.SHT_NOTE
        else
            elf.SHT_PROGBITS;

        elf_obj.appendSection(arena, .{
            .sh_name = name_idx,
            .sh_type = sh_type,
            .sh_flags = 0,
            .sh_addr = 0,
            .sh_link = .undef,
            .sh_info = 0,
            .sh_addralign = 1,
            .sh_entsize = 0,
            .contents = .{ .file = add_file },
        }) catch |err| switch (err) {
            error.OutOfMemory => unreachable,
        };
    }

    // Set section flags
    // @Todo fail on no matches? Would it prevent bugs?
    for (elf_obj.shdr_table.items) |ref| {
        const section = ref.get(elf_obj);
        for (opt_set_section_flags.items) |set_flags| {
            if (strEql(set_flags.section_name, section.name(elf_obj))) {
                ElfObj.setSectionFlags(section, set_flags.flags, elf_obj.header.machine == .X86_64);
            }
        }
    }

    try elf_obj.computeFinalLayout(arena);

    std.debug.print("{f}\n", .{elf_obj});

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

const SectionFlags = packed struct {
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

    // Program/Section header tables are stored in native-endian format,
    // and depending on target endianness must be byte-swapped on write.
    // Same order as in the input.

    phdr_table: []elf.Elf64_Phdr,

    /// Ordered list of section headers in output
    shdr_table: std.ArrayList(Shdr.Ref),
    /// Backing memory for section headers
    shdr_buf: std.ArrayList(Shdr),

    removed_sections: std.ArrayList(Shdr.Ref),

    shstrtab: Shdr.Ref,

    fn appendSection(obj: *ElfObj, arena: std.mem.Allocator, section: Shdr) !void {
        try obj.shdr_buf.append(arena, section);
        const idx: elf.Word = @intCast(obj.shdr_buf.items.len - 1);
        try obj.shdr_table.append(arena, @enumFromInt(idx));
    }

    pub fn read(allocator: std.mem.Allocator, file_reader: *std.fs.File.Reader) !ElfObj {
        const header = try elf.Header.read(&file_reader.interface);

        // @Todo can we work around this? Are there use cases for running objcopy on files without a shstrtab?
        if (header.shstrndx == elf.SHN_UNDEF)
            fatal("missing section .shstrtab: zig objcopy requires the section name string table in order to run", .{});

        const phdrs = try allocator.alloc(elf.Elf64_Phdr, header.phnum);
        errdefer allocator.free(phdrs);
        const shdrs = try allocator.alloc(Shdr, header.shnum);
        errdefer allocator.free(shdrs);
        const shdr_refs = try allocator.alloc(Shdr.Ref, header.shnum);
        errdefer allocator.free(shdr_refs);

        var i: usize = 0;
        var ph_iter = header.iterateProgramHeaders(file_reader);
        while (try ph_iter.next()) |ph| : (i += 1) phdrs[i] = ph;
        std.debug.assert(i == header.phnum);

        i = 0;
        var sh_iter = header.iterateSectionHeaders(file_reader);
        while (try sh_iter.next()) |sh| : (i += 1) {
            shdr_refs[i] = @enumFromInt(i);
            shdrs[i] = .{
                .sh_name = sh.sh_name,
                .sh_type = sh.sh_type,
                .sh_flags = sh.sh_flags,
                .sh_addr = sh.sh_addr,
                .sh_link = @enumFromInt(sh.sh_link),
                .sh_info = sh.sh_info,
                .sh_addralign = sh.sh_addralign,
                .sh_entsize = sh.sh_entsize,
                .original_offset = sh.sh_offset,
                .original_size = sh.sh_size,
                .contents = .original,
            };

            switch (sh.sh_type) {
                elf.SHT_SYMTAB, elf.SHT_DYNSYM => shdrs[i].contents = .{
                    .symtab = try .read(allocator, header, file_reader, shdrs[i]),
                },
                elf.SHT_STRTAB => {
                    var w: std.Io.Writer.Allocating = try .initCapacity(allocator, shdrs[i].original_size);
                    errdefer w.deinit();
                    try file_reader.seekTo(shdrs[i].original_offset);
                    try file_reader.interface.streamExact(&w.writer, shdrs[i].original_size);
                    shdrs[i].contents = .{ .strtab = w.toArrayList() };
                },
                elf.SHT_REL, elf.SHT_RELA => shdrs[i].contents = .{
                    .relocs = try .read(allocator, header, file_reader, shdrs[i]),
                },
                elf.SHT_GROUP => shdrs[i].contents = .{
                    .group = try .read(allocator, header, file_reader, shdrs[i]),
                },
                else => {},
            }
        }
        std.debug.assert(i == header.shnum);

        return .{
            .header = header,
            .phdr_table = phdrs,
            .shdr_table = .fromOwnedSlice(shdr_refs),
            .shdr_buf = .fromOwnedSlice(shdrs),
            .shstrtab = @enumFromInt(header.shstrndx),
            .removed_sections = .empty,
        };
    }

    pub fn computeFinalLayout(obj: *ElfObj, allocator: std.mem.Allocator) !void {
        obj.header.phnum = @intCast(obj.phdr_table.len);
        obj.header.shnum = @intCast(obj.shdr_table.items.len);

        var offset: usize = 0;

        offset += if (obj.header.is_64)
            @sizeOf(elf.Elf64_Ehdr)
        else
            @sizeOf(elf.Elf32_Ehdr);

        obj.header.phoff = if (obj.header.phnum > 0) offset else 0;
        offset += obj.header.phentsize * obj.header.phnum;

        // Contents should be written in ascending offset order.
        const shdrs_sorted_by_content_offset = try allocator.dupe(Shdr.Ref, obj.shdr_table.items);
        defer allocator.free(shdrs_sorted_by_content_offset);
        std.mem.sort(Shdr.Ref, shdrs_sorted_by_content_offset, obj, struct {
            pub fn lessThan(o: *const ElfObj, a: Shdr.Ref, b: Shdr.Ref) bool {
                // sections with `null_offset`s will be sorted to the end
                return a.get(o.*).original_offset < b.get(o.*).original_offset;
            }
        }.lessThan);

        // Whether the section table comes before or after the contents is largely arbitrary,
        // but most educational materials show the table at the end.
        for (shdrs_sorted_by_content_offset) |ref| {
            const section = ref.get(obj.*);
            if (section.sh_type == elf.SHT_NULL) {
                section.final_offset = 0;
                continue;
            }

            const alignment: std.mem.Alignment = .fromByteUnits(@max(1, section.sh_addralign));
            offset = alignment.forward(offset);
            section.final_offset = offset;

            section.final_size = size: {
                switch (section.contents) {
                    .original => break :size section.original_size,
                    .file => |file| {
                        const stat = try file.stat(); // @Todo cache this when adding the section?
                        break :size stat.size;
                    },
                    .symtab => |symtab| break :size symtab.symbols.items.len * section.sh_entsize,
                    .strtab => |strtab| break :size strtab.items.len,
                    .relocs => |relocs| break :size relocs.entries.items.len * section.sh_entsize,
                    .group => |group| break :size (group.sections.items.len + 1) * @sizeOf(elf.Word),
                }
            };
            offset += section.final_size;
        }

        for (obj.shdr_table.items, 0..) |ref, i| {
            ref.get(obj.*).final_index = @intCast(i);
        }

        obj.header.shstrndx = @intCast(obj.shstrtab.get(obj.*).final_index);

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

                try output.interface.flush();
                try output.seekTo(obj.header.phoff);
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

                for (obj.shdr_table.items) |ref| {
                    const section = ref.get(obj);
                    std.debug.assert(section.final_offset != Shdr.null_offset);
                    try output.interface.flush();
                    try output.seekTo(section.final_offset);

                    switch (section.contents) {
                        .original => {
                            // pull unmodified data from input
                            std.debug.assert(section.original_offset != Shdr.null_offset);
                            try input.seekTo(section.original_offset);
                            _ = try output.interface.sendFileAll(input, .limited64(section.original_size));
                        },
                        .file => |file| {
                            defer file.close();
                            var buf: [1024]u8 = undefined; // @Performance does this need a buffer?
                            var file_reader = file.reader(&buf);
                            _ = try output.interface.sendFileAll(&file_reader, .unlimited);
                        },
                        .symtab => |symtab| {
                            for (symtab.symbols.items) |sym| {
                                const tgt_sym: if (is_64) elf.Elf64_Sym else elf.Elf32_Sym = .{
                                    .st_name = sym.st_name,
                                    .st_info = sym.st_info,
                                    .st_other = sym.st_other,
                                    .st_shndx = switch (sym.st_shndx) {
                                        .abs, .common, .xindex => |val| @intFromEnum(val),
                                        else => @intCast(sym.st_shndx.get(obj).final_index),
                                    },
                                    .st_value = @intCast(sym.st_value),
                                    .st_size = @intCast(sym.st_size),
                                };
                                try output.interface.writeStruct(tgt_sym, obj.header.endian);
                            }
                        },
                        .strtab => |strtab| try output.interface.writeAll(strtab.items),
                        .relocs => |relocs| {
                            for (relocs.entries.items) |rel| {
                                const RelT = if (is_64) elf.Elf64_Rela else elf.Elf32_Rela;

                                try output.interface.writeInt(
                                    @FieldType(RelT, "r_offset"),
                                    @intCast(rel.r_offset),
                                    obj.header.endian,
                                );
                                try output.interface.writeInt(
                                    @FieldType(RelT, "r_info"),
                                    @intCast(rel.r_info),
                                    obj.header.endian,
                                );
                                if (relocs.addend) {
                                    try output.interface.writeInt(
                                        @FieldType(RelT, "r_addend"),
                                        @intCast(rel.r_addend),
                                        obj.header.endian,
                                    );
                                }
                            }
                        },
                        .group => |group| {
                            try output.interface.writeInt(elf.Word, group.flags, obj.header.endian);
                            for (group.sections.items) |member_ref| {
                                try output.interface.writeInt(
                                    elf.Word,
                                    member_ref.get(obj).final_index,
                                    obj.header.endian,
                                );
                            }
                        },
                    }
                }

                try output.interface.flush();
                try output.seekTo(obj.header.shoff);
                for (obj.shdr_table.items) |ref| {
                    const section = ref.get(obj);
                    const shdr: if (is_64) elf.Elf64_Shdr else elf.Elf32_Shdr = .{
                        .sh_name = section.sh_name,
                        .sh_type = section.sh_type,
                        .sh_flags = @intCast(section.sh_flags),
                        .sh_addr = @intCast(section.sh_addr),
                        .sh_offset = @intCast(section.final_offset),
                        .sh_size = @intCast(section.final_size),
                        .sh_link = switch (section.sh_link) {
                            .undef => elf.SHN_UNDEF,
                            else => section.sh_link.get(obj).final_index,
                        },
                        .sh_info = section.sh_info,
                        .sh_addralign = @intCast(section.sh_addralign),
                        .sh_entsize = @intCast(section.sh_entsize),
                    };
                    try output.interface.writeStruct(shdr, obj.header.endian);
                }
            },
        }
    }

    fn getShStringTable(obj: ElfObj) []const u8 {
        return obj.shstrtab.get(obj).contents.strtab.items;
    }

    fn insertShString(
        obj: ElfObj,
        // @Todo ElfObj should probably have it's own allocator
        allocator: std.mem.Allocator,
        str: []const u8,
    ) !u32 {
        const shstrtab_buffer = &obj.shstrtab.get(obj).contents.strtab;
        try shstrtab_buffer.ensureUnusedCapacity(allocator, str.len + 1);

        const str_idx: u32 = @intCast(shstrtab_buffer.items.len);
        shstrtab_buffer.appendSliceAssumeCapacity(str);
        shstrtab_buffer.appendAssumeCapacity(0);
        return str_idx;
    }

    fn getStrTabEntry(strtab: []const u8, off: u32) [:0]const u8 {
        const slice = strtab[off..];
        return slice[0..std.mem.indexOfScalar(u8, slice, 0).? :0];
    }

    const Shdr = struct {
        sh_name: elf.Word,
        sh_type: elf.Word,
        sh_flags: elf.Elf64_Xword,
        sh_addr: elf.Elf64_Addr,

        sh_link: Ref,
        sh_info: elf.Word,

        sh_addralign: elf.Elf64_Xword,
        sh_entsize: elf.Elf64_Xword,

        // @Incomplete store in PWP manner. Common types use shared pools (e.g. all strtabs are backed by one arraylist)
        contents: union(enum) {
            /// Untracked contents
            original,
            /// Use contents from a file
            file: std.fs.File,
            // @Todo there can only be one section of each type, so they can be stored in ElfObj instead
            /// SHT_SYMTAB or SHT_DYNSYM
            symtab: SymtabSection,
            /// SHT_STRTAB
            strtab: std.ArrayList(u8),
            /// SHT_REL or SHT_RELA
            relocs: RelocationSection,
            /// SHT_GROUP
            group: GroupSection,
        },

        /// Used to convert a section reference to an index.
        /// Only valid after calling `ElfObj.computeFinalLayout()`.
        final_index: elf.Word = elf.SHN_UNDEF,
        /// Only valid after calling `ElfObj.computeFinalLayout()`.
        final_offset: elf.Elf64_Off = null_offset,
        /// Only valid after calling `ElfObj.computeFinalLayout()`.
        final_size: elf.Elf64_Xword = 0,

        /// Original `sh_offset` field. Used for reading data from the input file.
        /// Sections that don't originate from the input should use the `null_offset` value.
        original_offset: elf.Elf64_Off = null_offset,
        /// Original `sh_offset` field. Used for reading data from the input file.
        original_size: elf.Elf64_Xword = 0,

        const null_offset = std.math.maxInt(elf.Elf64_Off);

        /// Stable Shdr reference.
        const Ref = enum(elf.Half) {
            undef = elf.SHN_UNDEF,

            // These only apply for index fields that are Half sized,
            // (i.e. st_shndx, e_shnum, and e_shstrndx), otherwise
            // they should be ignored and the index treated as normal.
            abs = elf.SHN_ABS,
            common = elf.SHN_COMMON,
            xindex = 0xffff,
            _,

            fn reserved(r: Ref) bool {
                const i = @intFromEnum(r);
                return elf.SHN_LORESERVE <= i and i <= elf.SHN_HIRESERVE;
            }

            fn get(r: Ref, obj: ElfObj) *Shdr {
                // It's fine if r == .undef since the null section is stored as well.
                return &obj.shdr_buf.items[@intFromEnum(r)];
            }
        };

        fn name(s: Shdr, obj: ElfObj) [:0]const u8 {
            return getStrTabEntry(obj.getShStringTable(), s.sh_name);
        }
    };

    pub fn setSectionFlags(sh: *Shdr, flags: SectionFlags, is_x86_64: bool) void {
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
            sh.sh_type = elf.SHT_PROGBITS;
        }
    }

    const Symbol = struct {
        st_name: elf.Word,
        st_info: u8,
        st_other: u8,
        st_shndx: Shdr.Ref,
        st_value: elf.Elf64_Addr,
        st_size: elf.Elf64_Xword,

        pub inline fn st_type(sym: Symbol) u4 {
            return @truncate(sym.st_info);
        }
        pub inline fn st_bind(sym: Symbol) u4 {
            return @truncate(sym.st_info >> 4);
        }
    };

    const SymtabSection = struct {
        symbols: std.ArrayList(Symbol),
        non_local_start_idx: usize,

        fn read(
            gpa: std.mem.Allocator,
            header: elf.Header,
            reader: *std.fs.File.Reader,
            sh: Shdr,
        ) !SymtabSection {
            if (sh.sh_link == .undef) fatal("invalid symbol table section header: bad sh_link", .{});
            const num_syms = sh.original_size / sh.sh_entsize;
            if (sh.sh_info > num_syms) fatal("invalid symbol table section header: bad sh_info", .{});

            var syms: std.ArrayList(Symbol) = try .initCapacity(gpa, num_syms);
            errdefer syms.deinit(gpa);

            try reader.seekTo(sh.original_offset);

            for (0..num_syms) |i| switch (header.is_64) {
                inline else => |is_64| {
                    const sym = reader.interface.takeStruct(
                        if (is_64) elf.Elf64_Sym else elf.Elf32_Sym,
                        header.endian,
                    ) catch |err| switch (err) {
                        error.EndOfStream => fatal("invalid symbol table section: unexpected EOF", .{}),
                        else => |e| return e,
                    };

                    const st_shndx: Shdr.Ref = @enumFromInt(sym.st_shndx);
                    if (st_shndx == .xindex) fatal(
                        "symbol [{d}] has st_shndx value 'SHN_XINDEX'. This feature is currently unsupported.",
                        .{i},
                    );

                    syms.appendAssumeCapacity(.{
                        .st_name = sym.st_name,
                        .st_info = sym.st_info,
                        .st_other = sym.st_other,
                        .st_shndx = st_shndx,
                        .st_value = sym.st_value,
                        .st_size = sym.st_size,
                    });
                },
            };

            return .{
                .symbols = syms,
                .non_local_start_idx = sh.sh_info,
            };
        }
    };

    const GroupSection = struct {
        flags: elf.Word,
        sections: std.ArrayList(Shdr.Ref),

        fn read(
            arena: std.mem.Allocator,
            header: elf.Header,
            reader: *std.fs.File.Reader,
            sh: Shdr,
        ) !GroupSection {
            const num_entries = sh.original_size / @sizeOf(elf.Word);
            const section_refs = try arena.alloc(Shdr.Ref, num_entries - 1);
            errdefer arena.free(section_refs);

            try reader.seekTo(sh.original_offset);
            const flags = try reader.interface.takeInt(elf.Word, header.endian);
            for (section_refs) |*ref| {
                ref.* = @enumFromInt(try reader.interface.takeInt(elf.Word, header.endian));
            }

            return .{ .flags = flags, .sections = .fromOwnedSlice(section_refs) };
        }
    };

    // @Incomplete handle shifting indices when adding/removing symbols.
    const Relocation = elf.Elf64_Rela;
    const RelocationSection = struct {
        // @Performance is there a smarter way of doing this that uses less memory?
        /// Reading the `r_addend` field of relocation entries is illegal unless
        /// this value is true.
        addend: bool,
        entries: std.ArrayList(Relocation),

        fn read(
            arena: std.mem.Allocator,
            header: elf.Header,
            reader: *std.fs.File.Reader,
            sh: Shdr,
        ) !RelocationSection {
            const addend = sh.sh_type == elf.SHT_RELA;

            const num_entries = sh.original_size / sh.sh_entsize;
            var entries: std.ArrayList(Relocation) = try .initCapacity(arena, num_entries);
            errdefer entries.deinit(arena);

            try reader.seekTo(sh.original_offset);
            for (0..num_entries) |_| switch (header.is_64) {
                inline else => |is_64| {
                    const RelT = if (is_64) elf.Elf64_Rela else elf.Elf32_Rela;

                    const rel = entries.addOneAssumeCapacity();
                    rel.r_offset = try reader.interface.takeInt(
                        @FieldType(RelT, "r_offset"),
                        header.endian,
                    );
                    rel.r_info = try reader.interface.takeInt(
                        @FieldType(RelT, "r_info"),
                        header.endian,
                    );
                    if (addend) {
                        rel.r_addend = try reader.interface.takeInt(
                            @FieldType(RelT, "r_addend"),
                            header.endian,
                        );
                    }
                },
            };

            return .{ .addend = addend, .entries = entries };
        }
    };

    pub fn format(obj: ElfObj, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (obj.shdr_table.items, 0..) |ref, i| {
            const section = ref.get(obj);

            const sh_type = switch (section.sh_type) {
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

            try writer.print(
                "[{d: >2}] name: {s: <20}, type: {s: <13}, ",
                .{ i, section.name(obj), sh_type },
            );
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
                    if (section.sh_flags & flag > 0) {
                        if (written > 0) {
                            try writer.writeByte('|');
                            written += 1;
                        }
                        try writer.writeAll(name);
                        written += name.len;
                    }
                }
                if (written == 0 and section.sh_flags > 0) {
                    var counter: std.Io.Writer.Discarding = .init(&.{});
                    counter.writer.print("0x{x}", .{section.sh_flags}) catch unreachable;
                    try writer.print("0x{x}", .{section.sh_flags});
                    written += @intCast(counter.count);
                }
                try writer.splatByteAll(' ', 15 -| written);
                try writer.writeAll(", ");
            }

            try writer.print("addr: 0x{x: <6}, offset: 0x{x: <6}, size: {d: <8}, " ++
                "link: {d: <4}, info: {d: <4}, addralign: {d: <4}, entsize: {d}\n", .{
                section.sh_addr,
                section.final_offset,
                section.final_size,
                section.sh_link.get(obj).final_index,
                section.sh_info,
                section.sh_addralign,
                section.sh_entsize,
            });
        }
    }
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

fn sliceContains(comptime T: type, slice: []const T, needle: T) bool {
    return std.mem.indexOfScalar(T, slice, needle) != null;
}
