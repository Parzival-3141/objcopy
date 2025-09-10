const std = @import("std");
const elf = std.elf;

pub fn main() !void {
    var arena_inst: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var args = try std.process.argsWithAllocator(arena);
    const self_path = args.next().?;
    const file_path = args.next() orelse self_path;

    const elf_obj = try std.fs.cwd().readFileAlloc(arena, file_path, 1024 * 1024 * 1024);
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
    while (try iter.next()) |section_hdr| {
        std.debug.assert(section_hdr.sh_name < string_table.len);
        const sh_name: []const u8 = if (section_hdr.sh_name != 0)
            std.mem.sliceTo(string_table[section_hdr.sh_name..], 0)
        else
            "null";

        const sh_type = switch (section_hdr.sh_type) {
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

        std.debug.print("name: {s: <20}, type: {s: <13}, flags: {f}," ++
            "addr: 0x{x: <6}, offset: 0x{x: <6}, size: {d: <8}," ++
            "link: {d: <4}, info: {d: <4}, addralign: {d: <4}," ++
            "entsize: {d}\n", .{
            sh_name,
            sh_type,
            Flags{ .val = section_hdr.sh_flags, .spacing = 15 },
            section_hdr.sh_addr,
            section_hdr.sh_offset,
            section_hdr.sh_size,
            section_hdr.sh_link,
            section_hdr.sh_info,
            section_hdr.sh_addralign,
            section_hdr.sh_entsize,
        });
    }
}

const Flags = struct {
    val: elf.Elf64_Xword,
    spacing: u8,

    pub fn format(f: Flags, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var written: u16 = 0;
        var matched_any: bool = false;
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
            if (f.val & flag > 0) {
                if (matched_any) {
                    try writer.writeAll("|");
                    written += 1;
                }
                matched_any = true;
                try writer.writeAll(name);
                written += name.len;
            }
        }
        if (!matched_any) {
            // try writer.writeAll("none");
            try writer.writeByte('0');
            written += 1;
        }
        try writer.splatByteAll(' ', f.spacing -| written);
    }
};

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
