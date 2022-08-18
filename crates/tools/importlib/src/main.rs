use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x100000;
const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x200000;
const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x300000;
const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x400000;
const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x500000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x40;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x2000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
const IMAGE_SYM_CLASS_STATIC: u8 = 3;
const IMAGE_SYM_CLASS_SECTION: u8 = 104;

const IMAGE_FILE_32BIT_MACHINE: u16 = 0x100;

const IMAGE_REL_I386_DIR32NB: u16 = 7;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 3;
const IMAGE_REL_ARM64_ADDR32NB: u16 = 2;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
enum Arch {
    X86,
    X64,
    ARM64,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
enum Env {
    Msvc,
    GnuLlvm,
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
struct Platform {
    arch: Arch,
    env: Env,
}

impl Platform {
    fn all() -> impl Iterator<Item = Platform> {
        IntoIterator::into_iter([
            Platform {
                arch: Arch::X64,
                env: Env::GnuLlvm,
            },
            Platform {
                arch: Arch::ARM64,
                env: Env::GnuLlvm,
            },
            Platform {
                arch: Arch::X64,
                env: Env::Msvc,
            },
            Platform {
                arch: Arch::ARM64,
                env: Env::Msvc,
            },
            Platform {
                arch: Arch::X86,
                env: Env::Msvc,
            },
        ])
    }

    fn libname(&self, name: &str) -> String {
        match self.env {
            Env::Msvc => format!("{}.lib", name),
            _ => format!("lib{}.a", name),
        }
    }

    fn machine(&self) -> u16 {
        match self.arch {
            Arch::X86 => 0x14c,
            Arch::X64 => 0x8664,
            Arch::ARM64 => 0xaa64,
        }
    }

    fn is_64bit(&self) -> bool {
        match self.arch {
            Arch::X86 => false,
            _ => true,
        }
    }

    fn relocation(&self) -> u16 {
        match self.arch {
            Arch::X86 => IMAGE_REL_I386_DIR32NB,
            Arch::X64 => IMAGE_REL_AMD64_ADDR32NB,
            Arch::ARM64 => IMAGE_REL_ARM64_ADDR32NB,
        }
    }
}

#[derive(Debug)]
struct UnknownPlatform;

impl TryFrom<&str> for Platform {
    type Error = UnknownPlatform;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let [env, cpu]: [&str; 2] = s.rsplitn(2, '_').collect::<Vec<_>>().try_into().map_err(|_| UnknownPlatform)?;
        Ok(Platform {
            arch: match cpu {
                "i686" => Arch::X86,
                "x86_64" => Arch::X64,
                "aarch64" => Arch::ARM64,
                _ => return Err(UnknownPlatform),
            },
            env: match env {
                "msvc" => Env::Msvc,
                "gnullvm" => Env::GnuLlvm,
                _ => return Err(UnknownPlatform),
            },
        })
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self.arch {
            Arch::X86 => "i686",
            Arch::X64 => "x86_64",
            Arch::ARM64 => "aarch64",
        }
        .fmt(f)?;
        "_".fmt(f)?;
        match self.env {
            Env::Msvc => "msvc",
            Env::GnuLlvm => "gnullvm",
        }
        .fmt(f)
    }
}

fn main() {
    let mut platforms = BTreeSet::new();
    for platform in std::env::args().skip(1) {
        if platform == "all" {
            platforms.extend(Platform::all());
        } else {
            platforms.insert(Platform::try_from(&*platform).unwrap());
        }
    }
    if platforms.is_empty() {
        eprintln!("Please specify at least one platform or use 'all' argument");
        return;
    };

    let libraries = lib::libraries();

    for platform in platforms {
        build_platform(platform, &libraries).unwrap();
    }
}

fn build_platform(platform: Platform, libraries: &BTreeMap<String, BTreeMap<String, lib::CallingConvention>>) -> std::io::Result<()> {
    eprintln!("{}", platform);

    let mut seen_symbols = HashSet::new();
    let members = libraries
        .iter()
        .map(|(library, functions)| library_members(platform, library, functions))
        .flatten()
        .map(|mut member| {
            if platform.env == Env::Msvc {
                member.symbols.retain(|sym| seen_symbols.insert(sym.clone()));
            }
            member
        })
        .collect::<Vec<_>>();
    let libpath = PathBuf::from(format!("crates/targets/{}/lib/{}", platform, platform.libname("windows")));
    let mut archive = BufWriter::new(File::create(libpath)?);
    archive.write_all(b"!<arch>\n")?;

    // First Linker Member
    let symbols = members.iter().map(|member| member.symbols.iter()).flatten();
    let symtab_size = symbols.clone().map(|symbol| symbol.len() + 1).sum::<usize>() + symbols.clone().count() * 4 + 4;
    if platform.env == Env::Msvc {
        write!(&mut archive, "{:<16}{:<24}{:<8o}{:<10}\x60\x0a", "/", 0, 0, symtab_size)?;
    } else {
        write!(&mut archive, "{:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}\x60\x0a", "/", 0, 0, 0, 0, symtab_size)?;
    }
    archive.write_all(&u32::try_from(symbols.clone().count()).unwrap().to_be_bytes())?;

    let mut name_offsets = BTreeMap::new();
    let mut long_names = vec![];
    for name in members.iter().map(|member| &*member.name) {
        if name.len() > 15 {
            if let Entry::Vacant(entry) = name_offsets.entry(name) {
                entry.insert(long_names.len());
                long_names.extend_from_slice(name.as_bytes());
                if platform.env == Env::Msvc {
                    long_names.push(0);
                } else {
                    long_names.extend_from_slice(b"/\n");
                }
            }
        }
    }
    let mut offset = 8 + 60 + ((symtab_size + 1) & !1) + 60 + ((long_names.len() + 1) & !1);
    let second_symtab_size = symtab_size + members.len() * 4 + 4 - 2 * symbols.clone().count();
    if platform.env == Env::Msvc {
        offset += 60 + (second_symtab_size + 1) & !1;
    }
    for member in &members {
        for _ in &member.symbols {
            archive.write_all(&u32::try_from(offset).unwrap().to_be_bytes())?;
        }
        offset += 60 + (member.content.len() + 1) & !1
    }
    for symbol in symbols.clone() {
        archive.write_all(symbol.as_bytes())?;
        archive.write_all(b"\0")?;
    }
    if symtab_size % 2 == 1 {
        archive.write_all(b"\n")?;
    }

    // Second Linker Member
    if platform.env == Env::Msvc {
        write!(&mut archive, "{:<16}{:<24}{:<8o}{:<10}\x60\x0a", "/", 0, 0, second_symtab_size)?;
        archive.write_all(&u32::try_from(members.len()).unwrap().to_le_bytes())?;
        let mut offset = 8 + 60 + ((symtab_size + 1) & !1) + 60 + ((long_names.len() + 1) & !1);
        offset += 60 + (second_symtab_size + 1) & !1;
        for member in &members {
            archive.write_all(&u32::try_from(offset).unwrap().to_le_bytes())?;
            offset += 60 + (member.content.len() + 1) & !1
        }
        archive.write_all(&u32::try_from(symbols.clone().count()).unwrap().to_le_bytes())?;
        let mut symbols = members
            .iter()
            .enumerate()
            .map(|(num, member)| member.symbols.iter().map(move |symbol| (symbol, num + 1)))
            .flatten()
            .collect::<Vec<_>>();
        symbols.sort();
        for (_, member_num) in &symbols {
            archive.write_all(&u16::try_from(*member_num).unwrap().to_le_bytes())?;
        }
        for (symbol, _) in symbols {
            archive.write_all(symbol.as_bytes())?;
            archive.write_all(b"\0")?;
        }
        if second_symtab_size % 2 == 1 {
            archive.write_all(b"\n")?;
        }
    }

    // Longnames Member
    if platform.env == Env::Msvc {
        write!(&mut archive, "{:<16}{:<24}{:<8o}{:<10}\x60\x0a", "//", 0, 0, long_names.len())?;
    } else {
        write!(&mut archive, "{:<48}{:<10}\x60\x0a", "//", long_names.len())?;
    }
    archive.write_all(&long_names)?;
    if long_names.len() % 2 == 1 {
        archive.write_all(b"\n")?;
    }

    // Other members
    for member in &members {
        let name = if member.name.len() > 15 {
            format!("/{}", name_offsets[&*member.name])
        } else {
            format!("{}/", member.name)
        };
        if platform.env == Env::Msvc {
            write!(&mut archive, "{:<16}{:<24}{:<8o}{:<10}\x60\x0a", name, 0, 0, member.content.len())?;
        } else {
            write!(
                &mut archive,
                "{:<16}{:<12}{:<6}{:<6}{:<8o}{:<10}\x60\x0a",
                name,
                0,
                0,
                0,
                0o644,
                member.content.len()
            )?;
        }
        archive.write_all(&member.content)?;
        if member.content.len() % 2 == 1 {
            archive.write_all(b"\n")?;
        }
    }
    Ok(())
}

struct Member {
    name: String,
    content: Vec<u8>,
    symbols: Vec<String>,
}

#[derive(Clone)]
enum Content {
    None,
    Zeroes(usize),
    Data(Vec<u8>),
}

impl Content {
    fn len(&self) -> usize {
        match self {
            Content::None => 0,
            Content::Zeroes(len) => *len,
            Content::Data(data) => data.len(),
        }
    }

    fn write_to(&self, buf: &mut Vec<u8>) {
        match self {
            Content::None => {}
            Content::Zeroes(len) => buf.resize(buf.len() + len, 0),
            Content::Data(data) => buf.extend_from_slice(data),
        }
    }
}

#[derive(Clone)]
struct Section<'a> {
    name: &'a str,
    data: Content,
    relocations: &'a [Relocation<'a>],
    characteristics: u32,
}

impl<'a> Section<'a> {
    fn new(name: &'a str) -> Self {
        Section {
            name,
            data: Content::None,
            relocations: &[],
            characteristics: 0,
        }
    }

    fn content(self, data: Content) -> Self {
        Section { data, ..self }
    }

    fn relocations(self, relocations: &'a [Relocation<'a>]) -> Self {
        Section { relocations, ..self }
    }

    fn characteristics(self, characteristics: u32) -> Self {
        Section { characteristics, ..self }
    }

    fn data(self) -> Self {
        Section {
            characteristics: self.characteristics | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
            ..self
        }
    }

    fn align(self, align: usize) -> Self {
        Section {
            characteristics: (self.characteristics & !0x700000)
                | match align {
                    1 => IMAGE_SCN_ALIGN_1BYTES,
                    2 => IMAGE_SCN_ALIGN_2BYTES,
                    4 => IMAGE_SCN_ALIGN_4BYTES,
                    8 => IMAGE_SCN_ALIGN_8BYTES,
                    16 => IMAGE_SCN_ALIGN_16BYTES,
                    _ => unimplemented!(),
                },
            ..self
        }
    }
}

#[derive(Clone)]
enum SectionNum<'a> {
    Undefined,
    Absolute,
    ByName(&'a str),
}

#[derive(Clone)]
struct Symbol<'a> {
    name: &'a str,
    value: u32,
    section: SectionNum<'a>,
    storage_class: u8,
}

impl<'a> Symbol<'a> {
    fn new(name: &'a str) -> Self {
        Symbol {
            name,
            value: 0,
            section: SectionNum::Undefined,
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
        }
    }

    fn value(self, value: u32) -> Self {
        Symbol { value, ..self }
    }

    fn section(self, name: &'a str) -> Self {
        Symbol {
            section: SectionNum::ByName(name),
            storage_class: IMAGE_SYM_CLASS_SECTION,
            ..self
        }
    }

    fn external(self) -> Self {
        Symbol {
            storage_class: IMAGE_SYM_CLASS_EXTERNAL,
            ..self
        }
    }

    fn storage_class(self, storage_class: u8) -> Self {
        Symbol { storage_class, ..self }
    }
}

struct Relocation<'a> {
    address: u32,
    symbol: &'a str,
    kind: u16,
}

const FILE_HEADER_SIZE: usize = 20;
const SECTION_SIZE: usize = 40;
const RELOCATION_SIZE: usize = 10;

fn object(name: &str, platform: Platform, sections: &[Section], symbols: &[Symbol]) -> Member {
    let mut result = Vec::with_capacity(512);

    // File Header
    result.extend_from_slice(&platform.machine().to_le_bytes()); // Machine
    result.extend_from_slice(&u16::try_from(sections.len()).unwrap().to_le_bytes()); // NumberOfSections
    result.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    result.extend_from_slice(
        &u32::try_from(
            FILE_HEADER_SIZE
                + sections.len() * SECTION_SIZE
                + sections
                    .iter()
                    .map(|section| section.data.len() + section.relocations.len() * RELOCATION_SIZE)
                    .sum::<usize>(),
        )
        .unwrap()
        .to_le_bytes(),
    ); // PointerToSymbolTable
    result.extend_from_slice(&u32::try_from(symbols.len()).unwrap().to_le_bytes()); // NumberOfSymbols
    result.extend_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader
    result.extend_from_slice(&(if platform.is_64bit() { 0u16 } else { IMAGE_FILE_32BIT_MACHINE }).to_le_bytes()); // Characteristics

    // Section Table
    let mut offset = FILE_HEADER_SIZE + sections.len() * SECTION_SIZE;
    let mut reloc_location = 0;
    for section in sections {
        let len = result.len();
        assert!(section.name.len() <= 8);
        result.extend_from_slice(section.name.as_bytes()); // Name
        result.resize(len + 8, 0); // Null-padding to 8 bytes
        result.extend_from_slice(&0u32.to_le_bytes()); // VirtualSize
        result.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
        result.extend_from_slice(&u32::try_from(section.data.len()).unwrap().to_le_bytes()); // SizeOfRawData
        if section.data.len() > 0 {
            result.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes()); // PointerToRawData
            offset += section.data.len();
        } else {
            result.extend_from_slice(&0u32.to_le_bytes()); // PointerToRawData
        }
        // PointerToRelocations
        if section.relocations.is_empty() {
            if platform.env == Env::Msvc && reloc_location > 0 {
                result.extend_from_slice(&u32::try_from(reloc_location).unwrap().to_le_bytes());
            } else {
                result.extend_from_slice(&0u32.to_le_bytes());
            }
        } else {
            result.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
            reloc_location = offset;
            offset += section.relocations.len() * RELOCATION_SIZE;
        }
        result.extend_from_slice(&0u32.to_le_bytes()); // PointerToLineNumbers
        result.extend_from_slice(&u16::try_from(section.relocations.len()).unwrap().to_le_bytes()); // NumberOfRelocations
        result.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLineNumbers
        result.extend_from_slice(&section.characteristics.to_le_bytes()); // Characteristics
    }

    for section in sections {
        section.data.write_to(&mut result);

        // Relocation Table
        for reloc in section.relocations {
            result.extend_from_slice(&reloc.address.to_le_bytes()); // VirtualAddress
            result.extend_from_slice(
                &u32::try_from(symbols.iter().position(|symbol| symbol.name == reloc.symbol).unwrap())
                    .unwrap()
                    .to_le_bytes(),
            ); // SymbolTableIndex
            result.extend_from_slice(&reloc.kind.to_le_bytes()); // Type
        }
    }

    // Symbol Table
    offset = 4;
    for symbol in symbols {
        if symbol.name.len() > 8 {
            result.extend_from_slice(&0u32.to_le_bytes()); // Name: Zeroes (offset in the string table)
            result.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes()); // Name: Offset
            offset += symbol.name.len() + 1;
        } else {
            let len = result.len();
            result.extend_from_slice(symbol.name.as_bytes()); // Name
            result.resize(len + 8, 0); // Null-padding to 8 bytes
        }
        result.extend_from_slice(&symbol.value.to_le_bytes()); // Value
        let section = match symbol.section {
            SectionNum::Undefined => 0u16,        // IMAGE_SYM_UNDEFINED
            SectionNum::Absolute => -1i16 as u16, // IMAGE_SYM_ABSOLUTE
            SectionNum::ByName(name) => u16::try_from(sections.iter().enumerate().find(|(_, section)| section.name == name).unwrap().0 + 1).unwrap(),
        };
        result.extend_from_slice(&section.to_le_bytes()); // Section
        result.extend_from_slice(&0u16.to_le_bytes()); // Type
        result.push(symbol.storage_class);
        result.push(0); // NumberOfAuxSymbols
    }

    // String table
    if offset > 4 {
        result.extend_from_slice(&u32::try_from(offset).unwrap().to_le_bytes());
        for symbol in symbols {
            if symbol.name.len() > 8 {
                result.extend_from_slice(symbol.name.as_bytes());
                result.push(0);
            }
        }
    }

    Member {
        name: name.to_owned(),
        content: result,
        symbols: symbols
            .iter()
            .filter_map(|symbol| {
                (symbol.storage_class == IMAGE_SYM_CLASS_EXTERNAL && matches!(symbol.section, SectionNum::ByName(_))).then(|| symbol.name.to_owned())
            })
            .collect(),
    }
}

fn library_members<'a>(platform: Platform, library: &str, functions: &'a BTreeMap<String, lib::CallingConvention>) -> Vec<Member> {
    let library = library.to_string();
    let lib_symbol = library.rfind('.').map(|pos| &library[..pos]).unwrap_or(&library);
    let library = library
        .contains('.')
        .then(|| library.clone())
        .unwrap_or_else(|| format!("{}.dll", library));
    let symbols = functions.iter().map(|(function, calling_convention)| {
        let symbol = match calling_convention {
            lib::CallingConvention::Stdcall(params) if platform.arch == Arch::X86 => Cow::Owned(format!("_{}@{}", function, params & !3)),
            _ if platform.arch == Arch::X86 => Cow::Owned(format!("_{}", function)),
            _ => Cow::Borrowed(function),
        };
        let imp_symbol = format!("__imp_{}", symbol);
        (symbol, imp_symbol)
    });

    let debug_s = Section::new(".debug$S")
        .content(Content::Data(debug_section(platform, &library)))
        .characteristics(IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ);
    let comp_id = Symbol {
        name: "@comp.id",
        value: if platform.arch == Arch::ARM64 { 16873857 } else { 16874081 },
        section: SectionNum::Absolute,
        storage_class: IMAGE_SYM_CLASS_STATIC,
    };
    let null_thunk_data = format!("\x7f{}_NULL_THUNK_DATA", lib_symbol);
    let null_thunk_data = Symbol::new(&null_thunk_data);
    let vasize = if platform.is_64bit() { 8 } else { 4 };
    let idata_value = if platform.env == Env::Msvc { 0xc0000040 } else { 0 };
    let skip = if platform.env == Env::Msvc { 0 } else { 1 };
    let members = [
        object(
            &library,
            platform,
            &[
                debug_s.clone(),
                Section::new(".idata$5").data().content(Content::Zeroes(vasize)).align(vasize),
                Section::new(".idata$4").data().content(Content::Zeroes(vasize)).align(vasize),
            ][skip..],
            &[comp_id.clone(), null_thunk_data.clone().section(".idata$5").external()][skip..],
        ),
        object(
            &library,
            platform,
            &[debug_s.clone(), Section::new(".idata$3").data().content(Content::Zeroes(20)).align(4)][skip..],
            &[comp_id.clone(), Symbol::new("__NULL_IMPORT_DESCRIPTOR").section(".idata$3").external()][skip..],
        ),
        object(
            &library,
            platform,
            &[
                debug_s.clone(),
                Section::new(".idata$2")
                    .data()
                    .content(Content::Zeroes(20))
                    .relocations(&[
                        Relocation {
                            address: 0x0c,
                            symbol: ".idata$6",
                            kind: platform.relocation(),
                        },
                        Relocation {
                            address: 0x0,
                            symbol: ".idata$4",
                            kind: platform.relocation(),
                        },
                        Relocation {
                            address: 0x10,
                            symbol: ".idata$5",
                            kind: platform.relocation(),
                        },
                    ])
                    .align(4),
                Section::new(".idata$6")
                    .data()
                    .content(Content::Data({
                        let mut data = format!("{}\0", library).into_bytes();
                        if platform.env == Env::Msvc && data.len() % 2 == 1 {
                            data.push(0);
                        }
                        data
                    }))
                    .align(2),
            ][skip..],
            &[
                comp_id.clone(),
                Symbol::new(&format!("__IMPORT_DESCRIPTOR_{}", lib_symbol)).section(".idata$2").external(),
                Symbol::new(".idata$2").value(idata_value).section(".idata$2"),
                Symbol::new(".idata$6").section(".idata$6").storage_class(IMAGE_SYM_CLASS_STATIC),
                Symbol::new(".idata$4").value(idata_value).storage_class(IMAGE_SYM_CLASS_SECTION),
                Symbol::new(".idata$5").value(idata_value).storage_class(IMAGE_SYM_CLASS_SECTION),
                Symbol::new("__NULL_IMPORT_DESCRIPTOR").external(),
                null_thunk_data.external(),
            ][skip..],
        ),
    ];
    let mut short_imports = symbols
        .enumerate()
        .rev()
        .map(move |(ordinal, (symbol, imp_symbol))| {
            let ordinal = if platform.env == Env::Msvc { ordinal } else { 0 };
            let mut symbols = vec![imp_symbol, symbol.clone().into_owned()];
            if platform.env == Env::Msvc {
                symbols.sort();
            }
            (
                symbol.clone().into_owned(),
                Member {
                    name: library.clone(),
                    content: short_import(platform, ordinal, &symbol, &library),
                    symbols,
                },
            )
        })
        .collect::<Vec<_>>();
    if platform.env == Env::Msvc {
        short_imports.sort_by(|a, b| a.0.cmp(&b.0).reverse());
    }
    let mut result = short_imports.into_iter().map(|(_, member)| member).chain(members).collect::<Vec<_>>();
    if platform.env == Env::GnuLlvm {
        result.reverse();
    }
    result
}

fn short_import(platform: Platform, ordinal: usize, function: &str, normalized_library: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(20 + function.len() + 1 + normalized_library.len() + 1);
    result.extend_from_slice(&0u16.to_le_bytes()); // Sig1: IMAGE_FILE_MACHINE_UNKNOWN
    result.extend_from_slice(&0xffffu16.to_le_bytes()); // Sig2
    result.extend_from_slice(&0u16.to_le_bytes()); // Version
    result.extend_from_slice(&platform.machine().to_le_bytes()); // Machine
    result.extend_from_slice(&0u32.to_le_bytes()); // Time-Date Stamp
    result.extend_from_slice(&u32::try_from(function.len() + 1 + normalized_library.len() + 1).unwrap().to_le_bytes()); // Size Of Data
    result.extend_from_slice(&u16::try_from(ordinal).unwrap().to_le_bytes()); // Ordinal/Hint
    if platform.arch == Arch::X86 {
        if function.contains('@') {
            result.extend_from_slice(&0b00000000000_011_00u16.to_le_bytes()); // 11bits Reserved, 3bits Name Type (IMPORT_NAME_UNDECORATE), 2bits Import Type (IMPORT_CODE)
        } else {
            result.extend_from_slice(&0b00000000000_010_00u16.to_le_bytes()); // 11bits Reserved, 3bits Name Type (IMPORT_NAME_NOPREFIX), 2bits Import Type (IMPORT_CODE)
        }
    } else {
        result.extend_from_slice(&0b00000000000_001_00u16.to_le_bytes()); // 11bits Reserved, 3bits Name Type (IMPORT_NAME), 2bits Import Type (IMPORT_CODE)
    }
    result.extend_from_slice(function.as_bytes());
    result.push(0);
    result.extend_from_slice(normalized_library.as_bytes());
    result.push(0);
    result
}

fn debug_section(platform: Platform, library: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(library.len() + 54);
    result.extend_from_slice(&2u32.to_le_bytes());
    result.extend_from_slice(&u16::try_from(library.len() + 7).unwrap().to_le_bytes());
    result.extend_from_slice(&9u16.to_le_bytes());
    result.extend_from_slice(&0u32.to_le_bytes());
    result.push(u8::try_from(library.len()).unwrap());
    result.extend_from_slice(library.as_bytes());
    result.extend_from_slice(&[b'\'', 0, 0x13, 0x10, 7, 0, 0, 0]);
    match platform.arch {
        Arch::X86 => result.push(0x3),
        Arch::X64 => result.push(0xd0),
        Arch::ARM64 => result.push(0xf6),
    }
    result.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0xe, 0]);
    if platform.arch == Arch::ARM64 {
        result.extend_from_slice(&[0x1f, 0, 0x81, 0x79]);
    } else {
        result.extend_from_slice(&[0x20, 0, 0x64, 0x7a]);
    }
    result.extend_from_slice(b"\x12Microsoft (R) LINK");
    assert_eq!(result.len(), library.len() + 54);
    result
}
