#include <iostream>
#include <fstream>
#include <vector>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <climits>

#define REBASE_OPCODE_DONE 0x00
#define REBASE_OPCODE_SET_TYPE_IMM 0x10
#define REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x20
#define REBASE_OPCODE_ADD_ADDR_ULEB 0x30
#define REBASE_OPCODE_ADD_ADDR_IMM_SCALED 0x40
#define REBASE_OPCODE_DO_REBASE_IMM_TIMES 0x50
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES 0x60
#define REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB 0x70
#define REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB 0x80

#define BIND_OPCODE_DONE 0x00
#define BIND_OPCODE_SET_DYLIB_ORDINAL_IMM 0x10
#define BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB 0x20
#define BIND_OPCODE_SET_RESOLVER 0x30
#define BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM 0x40
#define BIND_OPCODE_SET_TYPE_IMM 0x50
#define BIND_OPCODE_SET_ADDEND_SLEB 0x60
#define BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB 0x70
#define BIND_OPCODE_ADD_ADDR_ULEB 0x80
#define BIND_OPCODE_DO_BIND 0x90
#define BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB 0xA0
#define BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED 0xB0
#define BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB 0xC0

std::vector<char> read_file(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << path << "\n";
        return {};
    }
    return std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

bool get_vmaddr_range(const char *macho_data, uint64_t &base_vmaddr, uint64_t &max_vmaddr)
{
    const auto *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    if (header->magic != MH_MAGIC_64)
    {
        std::cerr << "Not a valid 64-bit Mach-O file.\n";
        return false;
    }

    base_vmaddr = UINT64_MAX;
    max_vmaddr = 0;

    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const auto *seg = reinterpret_cast<const segment_command_64 *>(cmd);
            if (seg->vmsize == 0)
            {
                cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
                continue;
            }
            if (seg->vmaddr < base_vmaddr)
                base_vmaddr = seg->vmaddr;
            uint64_t segment_end = seg->vmaddr + seg->vmsize;
            if (segment_end > max_vmaddr)
                max_vmaddr = segment_end;
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (base_vmaddr == UINT64_MAX)
    {
        std::cerr << "No segments found in Mach-O file.\n";
        return false;
    }
    if (base_vmaddr == 0)
    {
        std::cout << "Warning: Base VM address is 0. Treating addresses as direct offsets.\n";
    }

    std::cout << "VM address range found:\n";
    std::cout << "  Base vmaddr: 0x" << std::hex << base_vmaddr << "\n";
    std::cout << "  Max vmaddr:  0x" << std::hex << max_vmaddr << std::dec << "\n";

    return true;
}

void *allocate_and_map_segments(const char *macho_data, uint64_t base_vmaddr, uint64_t max_vmaddr)
{
    size_t size = max_vmaddr - base_vmaddr;
    void *mem = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        return nullptr;
    }

    std::cout << "Allocated memory block at " << mem << " of size " << size << " bytes\n";

    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const segment_command_64 *seg = reinterpret_cast<const segment_command_64 *>(cmd);
            uint64_t seg_vmaddr = seg->vmaddr;
            uint64_t seg_vmsize = seg->vmsize;
            uint64_t seg_fileoff = seg->fileoff;
            uint64_t seg_filesize = seg->filesize;

            void *dest = reinterpret_cast<uint8_t *>(mem) + (seg_vmaddr - base_vmaddr);
            const void *src = macho_data + seg_fileoff;

            std::cout << "Mapping segment: " << seg->segname << " at offset 0x"
                      << std::hex << seg_fileoff << " size: 0x" << seg_vmsize
                      << " file size: 0x" << seg_filesize << std::dec
                      << " protections: " << (seg->initprot & VM_PROT_READ ? "R" : "")
                      << (seg->initprot & VM_PROT_WRITE ? "W" : "")
                      << (seg->initprot & VM_PROT_EXECUTE ? "X" : "") << "\n";

            if (seg_filesize > 0)
            {
                memcpy(dest, src, seg_filesize);
            }

            int prot = 0;
            if (seg->initprot & VM_PROT_READ)
                prot |= PROT_READ;
            if (seg->initprot & VM_PROT_WRITE)
                prot |= PROT_WRITE;
            if (seg->initprot & VM_PROT_EXECUTE)
                prot |= PROT_EXEC;

            size_t pagesize = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = reinterpret_cast<uintptr_t>(dest) & ~(pagesize - 1);
            size_t prot_size = ((seg_vmsize + (reinterpret_cast<uintptr_t>(dest) - page_start) + pagesize - 1) & ~(pagesize - 1));

            if (mprotect(reinterpret_cast<void *>(page_start), prot_size, prot) != 0)
            {
                perror("mprotect");
                std::cerr << "Segment mapping failed for " << seg->segname << "\n";
                munmap(mem, size);
                return nullptr;
            }
            std::cout << "Applied protections for " << seg->segname << ": " << prot << "\n";
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    return mem;
}

uint64_t read_uleb128(const uint8_t *&p, const uint8_t *end)
{
    if (p >= end)
    {
        std::cerr << "ULEB128 read past end of buffer\n";
        return 0;
    }
    uint64_t result = 0;
    int bit = 0;
    while (p < end)
    {
        uint8_t byte = *p++;
        result |= (uint64_t)(byte & 0x7f) << bit;
        if ((byte & 0x80) == 0)
            break;
        bit += 7;
    }
    return result;
}

int64_t read_sleb128(const uint8_t *&p, const uint8_t *end)
{
    if (p >= end)
    {
        std::cerr << "SLEB128 read past end of buffer\n";
        return 0;
    }
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do
    {
        byte = *p++;
        result |= ((int64_t)(byte & 0x7f)) << bit;
        bit += 7;
    } while (byte & 0x80 && p < end);

    if ((byte & 0x40) != 0)
    {
        result |= (-1LL) << bit;
    }
    return result;
}

bool perform_rebase(void *base_memory, uint64_t base_vmaddr, uint64_t max_vmaddr, const uint8_t *rebase_info, size_t rebase_size)
{
    if (!base_memory || !rebase_info || rebase_size == 0)
    {
        std::cerr << "Invalid rebase parameters\n";
        return false;
    }

    const uint8_t *p = rebase_info;
    const uint8_t *end = rebase_info + rebase_size;

    uint8_t type = 0;
    uint64_t segment_index = 0;
    uint64_t segment_offset = 0;

    while (p < end)
    {
        uint8_t opcode = *p & 0xF0;
        uint8_t immediate = *p & 0x0F;
        ++p;

        std::cout << "Processing rebase opcode: 0x" << std::hex << (int)opcode << " immediate: " << (int)immediate << std::dec << "\n";

        switch (opcode)
        {
        case REBASE_OPCODE_DONE:
            std::cout << "Rebase complete\n";
            return true;

        case REBASE_OPCODE_SET_TYPE_IMM:
            type = immediate;
            std::cout << "Set type: " << (int)type << "\n";
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segment_index = immediate;
            segment_offset = read_uleb128(p, end);
            std::cout << "Set segment: " << segment_index << " offset: 0x" << std::hex << segment_offset << std::dec << "\n";
            break;

        case REBASE_OPCODE_ADD_ADDR_ULEB:
            segment_offset += read_uleb128(p, end);
            std::cout << "Add addr: 0x" << std::hex << segment_offset << std::dec << "\n";
            break;

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            segment_offset += immediate * sizeof(void *);
            std::cout << "Add addr scaled: 0x" << std::hex << segment_offset << std::dec << "\n";
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            for (int i = 0; i < immediate; i++)
            {
                if (segment_offset >= (max_vmaddr - base_vmaddr))
                {
                    std::cerr << "Rebase offset 0x" << std::hex << segment_offset << " out of bounds\n";
                    return false;
                }
                uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                uintptr_t old_value = *target;
                if (old_value >= max_vmaddr && old_value != 0)
                {
                    std::cerr << "Skipping invalid pointer value 0x" << std::hex << old_value
                              << " at target 0x" << (void *)target
                              << ", expected VM address < 0x" << max_vmaddr << std::dec << "\n";
                    segment_offset += sizeof(void *);
                    continue;
                }
                std::cout << "Rebasing at target: " << (void *)target << " value: 0x" << std::hex << old_value << std::dec << "\n";
                *target = old_value ? old_value + (uintptr_t)base_memory : (uintptr_t)base_memory;
                segment_offset += sizeof(void *);
            }
            break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {
            uint64_t count = read_uleb128(p, end);
            std::cout << "Rebase count: " << count << "\n";
            for (uint64_t i = 0; i < count; i++)
            {
                if (segment_offset >= (max_vmaddr - base_vmaddr))
                {
                    std::cerr << "Rebase offset 0x" << std::hex << segment_offset << " out of bounds\n";
                    return false;
                }
                uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                uintptr_t old_value = *target;
                if (old_value >= max_vmaddr && old_value != 0)
                {
                    std::cerr << "Skipping invalid pointer value 0x" << std::hex << old_value
                              << " at target 0x" << (void *)target
                              << ", expected VM address < 0x" << max_vmaddr << std::dec << "\n";
                    segment_offset += sizeof(void *);
                    continue;
                }
                std::cout << "Rebasing at target: " << (void *)target << " value: 0x" << std::hex << old_value << std::dec << "\n";
                *target = old_value ? old_value + (uintptr_t)base_memory : (uintptr_t)base_memory;
                segment_offset += sizeof(void *);
            }
        }
        break;

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {
            if (segment_offset >= (max_vmaddr - base_vmaddr))
            {
                std::cerr << "Rebase offset 0x" << std::hex << segment_offset << " out of bounds\n";
                return false;
            }
            uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
            uintptr_t old_value = *target;
            if (old_value >= max_vmaddr && old_value != 0)
            {
                std::cerr << "Skipping invalid pointer value 0x" << std::hex << old_value
                          << " at target 0x" << (void *)target
                          << ", expected VM address < 0x" << max_vmaddr << std::dec << "\n";
                segment_offset += sizeof(void *) + read_uleb128(p, end);
                continue;
            }
            std::cout << "Rebasing at target: " << (void *)target << " value: 0x" << std::hex << old_value << std::dec << "\n";
            *target = old_value ? old_value + (uintptr_t)base_memory : (uintptr_t)base_memory;
            segment_offset += sizeof(void *) + read_uleb128(p, end);
        }
        break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {
            uint64_t count = read_uleb128(p, end);
            uint64_t skip = read_uleb128(p, end);
            std::cout << "Rebase count: " << count << " skip: " << skip << "\n";
            for (uint64_t i = 0; i < count; i++)
            {
                if (segment_offset >= (max_vmaddr - base_vmaddr))
                {
                    std::cerr << "Rebase offset 0x" << std::hex << segment_offset << " out of bounds\n";
                    return false;
                }
                uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                uintptr_t old_value = *target;
                if (old_value >= max_vmaddr && old_value != 0)
                {
                    std::cerr << "Skipping invalid pointer value 0x" << std::hex << old_value
                              << " at target 0x" << (void *)target
                              << ", expected VM address < 0x" << max_vmaddr << std::dec << "\n";
                    segment_offset += skip + sizeof(void *);
                    continue;
                }
                std::cout << "Rebasing at target: " << (void *)target << " value: 0x" << std::hex << old_value << std::dec << "\n";
                *target = old_value ? old_value + (uintptr_t)base_memory : (uintptr_t)base_memory;
                segment_offset += skip + sizeof(void *);
            }
        }
        break;

        default:
            std::cerr << "Unknown rebase opcode: 0x" << std::hex << (int)opcode << std::dec << "\n";
            return false;
        }
    }
    std::cout << "Rebase reached end of buffer\n";
    return true;
}

bool perform_bind(void *base_memory, uint64_t base_vmaddr, uint64_t max_vmaddr, const uint8_t *bind_info, size_t bind_size)
{
    void *libc_handle = dlopen("/usr/lib/libc.dylib", RTLD_LAZY);
    if (!libc_handle)
    {
        std::cerr << "Failed to load libc.dylib: " << dlerror() << "\n";
        return false;
    }

    const uint8_t *p = bind_info;
    const uint8_t *end = bind_info + bind_size;

    uint8_t type = 0;
    uint64_t segment_index = 0;
    uint64_t segment_offset = 0;
    int64_t addend = 0;
    int library_ordinal = 0;
    std::string symbol_name;
    bool done = false;

    while (p < end && !done)
    {
        uint8_t opcode = *p & 0xF0;
        uint8_t immediate = *p & 0x0F;
        ++p;

        switch (opcode)
        {
        case BIND_OPCODE_DONE:
            done = true;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            library_ordinal = immediate;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            library_ordinal = (int)read_uleb128(p, end);
            break;

        case BIND_OPCODE_SET_RESOLVER:
            break;

        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
        {
            symbol_name.clear();
            while (*p != 0 && p < end)
            {
                symbol_name.push_back(*p++);
            }
            ++p; // skip null terminator
            break;
        }

        case BIND_OPCODE_SET_TYPE_IMM:
            type = immediate;
            break;

        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb128(p, end);
            break;

        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segment_index = immediate;
            segment_offset = read_uleb128(p, end);
            break;

        case BIND_OPCODE_ADD_ADDR_ULEB:
            segment_offset += read_uleb128(p, end);
            break;

        case BIND_OPCODE_DO_BIND:
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {
            if (segment_offset >= (max_vmaddr - base_vmaddr))
            {
                std::cerr << "Bind offset 0x" << std::hex << segment_offset << " out of bounds\n";
                dlclose(libc_handle);
                return false;
            }
            uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
            void *sym_addr = dlsym(library_ordinal == 0 ? RTLD_DEFAULT : libc_handle, symbol_name.c_str());
            std::cout << "Binding symbol: " << symbol_name << " (ordinal: " << library_ordinal
                      << ") to address: " << sym_addr << " at target: " << (void *)target << "\n";
            if (!sym_addr)
            {
                std::cerr << "Failed to bind symbol: " << symbol_name << " (" << dlerror() << ")\n";
                dlclose(libc_handle);
                return false;
            }
            *target = (uintptr_t)sym_addr + addend;

            if (opcode == BIND_OPCODE_DO_BIND)
            {
                segment_offset += sizeof(void *);
            }
            else if (opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB)
            {
                segment_offset += sizeof(void *) + read_uleb128(p, end);
            }
            else if (opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED)
            {
                segment_offset += sizeof(void *) + immediate * sizeof(void *);
            }
            else if (opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB)
            {
                uint64_t count = read_uleb128(p, end);
                uint64_t skip = read_uleb128(p, end);
                for (uint64_t i = 0; i < count; i++)
                {
                    if (segment_offset >= (max_vmaddr - base_vmaddr))
                    {
                        std::cerr << "Bind offset 0x" << std::hex << segment_offset << " out of bounds\n";
                        dlclose(libc_handle);
                        return false;
                    }
                    uintptr_t *t = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                    void *s_addr = dlsym(library_ordinal == 0 ? RTLD_DEFAULT : libc_handle, symbol_name.c_str());
                    std::cout << "Binding symbol (multi): " << symbol_name << " (ordinal: " << library_ordinal
                              << ") to address: " << s_addr << " at target: " << (void *)t << "\n";
                    if (!s_addr)
                    {
                        std::cerr << "Failed to bind symbol: " << symbol_name << " (" << dlerror() << ")\n";
                        dlclose(libc_handle);
                        return false;
                    }
                    *t = (uintptr_t)s_addr + addend;
                    segment_offset += skip + sizeof(void *);
                }
            }
        }
        break;

        default:
            std::cerr << "Unknown bind opcode: 0x" << std::hex << (int)opcode << std::dec << "\n";
            dlclose(libc_handle);
            return false;
        }
    }

    dlclose(libc_handle);
    return true;
}

void load_required_dylibs(const char *macho_data)
{
    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (cmd->cmd == LC_LOAD_DYLIB)
        {
            const dylib_command *dylib_cmd = reinterpret_cast<const dylib_command *>(cmd);
            const char *dylib_name = reinterpret_cast<const char *>(cmd) + dylib_cmd->dylib.name.offset;
            std::cout << "Loading dylib: " << dylib_name << "\n";
            void *handle = dlopen(dylib_name, RTLD_LAZY);
            if (!handle)
            {
                std::cerr << "Failed to load dylib " << dylib_name << ": " << dlerror() << "\n";
            }
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }
}

bool manual_bind_stubs(void *base_memory, const char *macho_data)
{
    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    void *libsystem_handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
    if (!libsystem_handle)
    {
        std::cerr << "Failed to load libSystem.B.dylib: " << dlerror() << "\n";
        return false;
    }

    const section_64 *stubs_section = nullptr;
    uint32_t *indirect_symtab = nullptr;
    const char *strtab = nullptr;
    const nlist_64 *symtab = nullptr;
    uint32_t indirect_symtab_size = 0;
    uint32_t nsyms = 0;

    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const segment_command_64 *seg = reinterpret_cast<const segment_command_64 *>(cmd);
            if (strcmp(seg->segname, "__TEXT") == 0)
            {
                const section_64 *sect = reinterpret_cast<const section_64 *>(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++)
                {
                    if (strcmp(sect[j].sectname, "__stubs") == 0)
                    {
                        stubs_section = &sect[j];
                        break;
                    }
                }
            }
        }
        else if (cmd->cmd == LC_DYSYMTAB)
        {
            const dysymtab_command *dysym = reinterpret_cast<const dysymtab_command *>(cmd);
            indirect_symtab = (uint32_t *)(macho_data + dysym->indirectsymoff);
            indirect_symtab_size = dysym->nindirectsyms;
        }
        else if (cmd->cmd == LC_SYMTAB)
        {
            const symtab_command *sym = reinterpret_cast<const symtab_command *>(cmd);
            strtab = macho_data + sym->stroff;
            symtab = (const nlist_64 *)(macho_data + sym->symoff);
            nsyms = sym->nsyms;
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (!stubs_section || !indirect_symtab || !strtab || !symtab)
    {
        std::cerr << "Failed to find stubs section, indirect symbol table, string table, or symbol table\n";
        dlclose(libsystem_handle);
        return false;
    }

    uint32_t stub_start_index = stubs_section->reserved1;
    uint32_t stub_size = stubs_section->reserved2 ? stubs_section->reserved2 : 12; // Default to 12 bytes
    uint32_t num_stubs = stubs_section->size / stub_size;

    // Allocate separate memory for stubs
    size_t stub_mem_size = num_stubs * stub_size;
    std::cout << "Attempting to allocate " << stub_mem_size << " bytes for stubs with RWX permissions\n";
    void *stub_memory = mmap(nullptr, stub_mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stub_memory == MAP_FAILED)
    {
        perror("mmap");
        std::cerr << "Failed to allocate memory for stubs. Ensure the executable has 'com.apple.security.cs.allow-jit' entitlement.\n";
        dlclose(libsystem_handle);
        return false;
    }

    std::cout << "Allocated stub memory at " << stub_memory << " of size " << stub_mem_size << " bytes\n";
    std::cout << "Processing " << num_stubs << " stubs, starting at index " << stub_start_index << "\n";

    bool binding_success = true;

    for (uint32_t i = 0; i < num_stubs && (stub_start_index + i) < indirect_symtab_size; ++i)
    {
        uint32_t sym_index = indirect_symtab[stub_start_index + i];
        if (sym_index >= nsyms)
        {
            std::cerr << "Invalid symbol index " << sym_index << " for stub " << i << "\n";
            binding_success = false;
            continue;
        }

        const char *symbol_name = strtab + symtab[sym_index].n_un.n_strx;
        if (symtab[sym_index].n_un.n_strx == 0 || symbol_name[0] == '\0')
        {
            std::cerr << "Empty or invalid symbol name for stub " << i << " at index " << sym_index << "\n";
            binding_success = false;
            continue;
        }

        std::cout << "Resolving symbol: " << symbol_name << " for stub " << i << " (index " << sym_index << ")\n";

        void *sym_addr = dlsym(libsystem_handle, symbol_name);
        if (!sym_addr)
        {
            std::cerr << "Failed to resolve symbol: " << symbol_name << " (" << dlerror() << ")\n";
            binding_success = false;
            continue;
        }

        uintptr_t stub_addr = (uintptr_t)stub_memory + (i * stub_size);
        std::cout << "Binding stub for " << symbol_name << " at 0x" << std::hex << stub_addr
                  << " to address 0x" << (uintptr_t)sym_addr << std::dec << "\n";

        // Write jump instruction (arm64: b <offset>)
        int64_t offset = ((uintptr_t)sym_addr - stub_addr) >> 2;
        if (offset > 0x07ffffff || offset < -0x08000000)
        {
            std::cerr << "Jump offset for " << symbol_name << " is too large\n";
            binding_success = false;
            continue;
        }
        uint32_t branch_instr = 0x14000000 | (offset & 0x03ffffff);
        *(uint32_t *)stub_addr = branch_instr;

        // Update original stub to branch to new stub
        uintptr_t orig_stub_addr = (uintptr_t)base_memory + stubs_section->addr + (i * stub_size);
        int64_t orig_offset = ((uintptr_t)stub_addr - orig_stub_addr) >> 2;
        if (orig_offset > 0x07ffffff || orig_offset < -0x08000000)
        {
            std::cerr << "Jump offset from original stub to new stub for " << symbol_name << " is too large\n";
            binding_success = false;
            continue;
        }
        uint32_t orig_branch_instr = 0x14000000 | (orig_offset & 0x03ffffff);

        // Temporarily make __TEXT writable
        size_t pagesize = sysconf(_SC_PAGESIZE);
        uintptr_t page_start = orig_stub_addr & ~(pagesize - 1);
        size_t prot_size = stub_size;
        if (mprotect((void *)page_start, prot_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        {
            perror("mprotect");
            std::cerr << "Failed to make stub at 0x" << std::hex << orig_stub_addr << " writable\n";
            binding_success = false;
            continue;
        }

        *(uint32_t *)orig_stub_addr = orig_branch_instr;

        // Restore __TEXT protections
        if (mprotect((void *)page_start, prot_size, PROT_READ | PROT_EXEC) != 0)
        {
            perror("mprotect");
            std::cerr << "Failed to restore protections for stub at 0x" << std::hex << orig_stub_addr << "\n";
        }
    }

    if (!binding_success)
    {
        std::cerr << "Some stub bindings failed\n";
        munmap(stub_memory, stub_mem_size);
        dlclose(libsystem_handle);
        return false;
    }

    dlclose(libsystem_handle);
    return true;
}

bool run_global_constructors(void *base_memory, uint64_t base_vmaddr, const char *macho_data)
{
    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    const section_64 *init_func_section = nullptr;
    const segment_command_64 *data_const_segment = nullptr;

    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const segment_command_64 *seg = reinterpret_cast<const segment_command_64 *>(cmd);
            if (strcmp(seg->segname, "__DATA_CONST") == 0)
            {
                data_const_segment = seg;
                const section_64 *sect = reinterpret_cast<const section_64 *>(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++)
                {
                    if (strcmp(sect[j].sectname, "__mod_init_func") == 0)
                    {
                        init_func_section = &sect[j];
                        break;
                    }
                }
            }
            if (init_func_section && data_const_segment)
            {
                break;
            }
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (!data_const_segment)
    {
        std::cout << "No __DATA_CONST segment found.\n";
        return false;
    }

    if (!init_func_section || init_func_section->size == 0)
    {
        std::cout << "No valid __mod_init_func section found.\n";
        return true;
    }

    uint64_t section_offset = init_func_section->addr - base_vmaddr;
    const uint64_t *func_ptrs = reinterpret_cast<const uint64_t *>((uint8_t *)base_memory + section_offset);
    size_t count = init_func_section->size / sizeof(uint64_t);

    std::cout << "Found " << count << " constructor pointers in __mod_init_func section.\n";

    for (size_t i = 0; i < count; i++)
    {
        uint64_t func_addr = func_ptrs[i];
        std::cout << "Constructor[" << i << "] = 0x" << std::hex << func_addr << std::dec << "\n";

        if (func_addr == 0)
        {
            std::cerr << "Skipping null constructor at index " << i << "\n";
            continue;
        }

        if (func_addr < base_vmaddr || func_addr >= base_vmaddr + (data_const_segment->vmaddr + data_const_segment->vmsize - base_vmaddr))
        {
            std::cerr << "Constructor address 0x" << std::hex << func_addr << " is outside valid segments\n";
            continue;
        }

        void (*ctor)() = reinterpret_cast<void (*)()>((uint8_t *)base_memory + (func_addr - base_vmaddr));

        // On arm64, functions are 4-byte aligned
        if (reinterpret_cast<uintptr_t>(ctor) % 4 != 0)
        {
            std::cerr << "Constructor pointer 0x" << std::hex << (void *)ctor << " is not 4-byte aligned\n";
            continue;
        }

        std::cout << "Calling ctor at VM addr: 0x" << std::hex << func_addr
                  << ", mem ptr: " << (void *)ctor << std::dec << "\n";

        try
        {
            ctor();
            std::cout << "ctor executed successfully\n";
        }
        catch (...)
        {
            std::cerr << "Exception or fault in constructor at index " << i << "\n";
            continue;
        }
    }

    return true;
}

uintptr_t find_symbol_address(const char *macho_data, const std::string &symbol_name, uint64_t base_vmaddr)
{
    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    const symtab_command *symtab = nullptr;

    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SYMTAB)
        {
            symtab = reinterpret_cast<const symtab_command *>(cmd);
            break;
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (!symtab)
    {
        std::cerr << "No symbol table found\n";
        return 0;
    }

    const nlist_64 *symbols = reinterpret_cast<const nlist_64 *>(macho_data + symtab->symoff);
    const char *string_table = macho_data + symtab->stroff;

    for (uint32_t i = 0; i < symtab->nsyms; i++)
    {
        const char *name = string_table + symbols[i].n_un.n_strx;
        if (symbol_name == std::string(name))
        {
            return symbols[i].n_value;
        }
    }

    std::cerr << "Symbol not found: " << symbol_name << "\n";
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <mach-o binary path>\n";
        return 1;
    }

    auto macho_data = read_file(argv[1]);
    if (macho_data.empty())
    {
        return 1;
    }

    uint64_t base_vmaddr = 0;
    uint64_t max_vmaddr = 0;
    if (!get_vmaddr_range(macho_data.data(), base_vmaddr, max_vmaddr))
    {
        return 1;
    }

    void *mapped_memory = allocate_and_map_segments(macho_data.data(), base_vmaddr, max_vmaddr);
    if (!mapped_memory)
    {
        return 1;
    }

    load_required_dylibs(macho_data.data());

    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data.data());
    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    const uint8_t *rebase_info = nullptr;
    size_t rebase_size = 0;
    const uint8_t *bind_info = nullptr;
    size_t bind_size = 0;
    const symtab_command *symtab_cmd = nullptr;
    const segment_command_64 *text_segment = nullptr;

    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (cmd->cmd == LC_DYLD_INFO || cmd->cmd == LC_DYLD_INFO_ONLY)
        {
            const dyld_info_command *dyld_cmd = reinterpret_cast<const dyld_info_command *>(cmd);
            rebase_info = (const uint8_t *)(macho_data.data() + dyld_cmd->rebase_off);
            rebase_size = dyld_cmd->rebase_size;
            bind_info = (const uint8_t *)(macho_data.data() + dyld_cmd->bind_off);
            bind_size = dyld_cmd->bind_size;
        }
        else if (cmd->cmd == LC_SYMTAB)
        {
            symtab_cmd = reinterpret_cast<const symtab_command *>(cmd);
        }
        else if (cmd->cmd == LC_SEGMENT_64)
        {
            const segment_command_64 *seg = reinterpret_cast<const segment_command_64 *>(cmd);
            if (strcmp(seg->segname, "__TEXT") == 0)
            {
                text_segment = seg;
            }
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (rebase_info && rebase_size > 0)
    {
        std::cout << "Performing rebase...\n";
        if (!perform_rebase(mapped_memory, base_vmaddr, max_vmaddr, rebase_info, rebase_size))
        {
            std::cerr << "Rebase failed, but continuing execution.\n";
        }
    }
    else
    {
        std::cout << "No rebase info found.\n";
    }

    if (bind_info && bind_size > 0)
    {
        std::cout << "Performing bind...\n";
        if (!perform_bind(mapped_memory, base_vmaddr, max_vmaddr, bind_info, bind_size))
        {
            std::cerr << "Bind failed.\n";
            munmap(mapped_memory, max_vmaddr - base_vmaddr);
            return 1;
        }
    }
    else
    {
        std::cout << "No bind info found.\n";
    }

    // Manually bind stubs for symbols like _printf
    if (!manual_bind_stubs(mapped_memory, macho_data.data()))
    {
        std::cerr << "Manual stub binding failed. Skipping constructors to avoid crashes.\n";
        munmap(mapped_memory, max_vmaddr - base_vmaddr);
        return 1;
    }

    if (!run_global_constructors(mapped_memory, base_vmaddr, macho_data.data()))
    {
        std::cerr << "Failed to run global constructors.\n";
        munmap(mapped_memory, max_vmaddr - base_vmaddr);
        return 1;
    }

    if (symtab_cmd)
    {
        const uint8_t *symtab_ptr = reinterpret_cast<const uint8_t *>(macho_data.data()) + symtab_cmd->symoff;
        const char *strtab_ptr = reinterpret_cast<const char *>(macho_data.data()) + symtab_cmd->stroff;
        uint32_t nsyms = symtab_cmd->nsyms;

        const struct nlist_64 *symbols = reinterpret_cast<const struct nlist_64 *>(symtab_ptr);
        const char *target_symbol = "_hello";

        void (*hello_func)() = nullptr;

        for (uint32_t i = 0; i < nsyms; ++i)
        {
            const struct nlist_64 &sym = symbols[i];
            if (sym.n_un.n_strx == 0)
                continue;

            const char *name = strtab_ptr + sym.n_un.n_strx;
            if (strcmp(name, target_symbol) == 0)
            {
                uint64_t sym_addr = sym.n_value;
                if (text_segment && (sym_addr < text_segment->vmaddr || sym_addr >= text_segment->vmaddr + text_segment->vmsize))
                {
                    std::cerr << "Symbol '_hello' at VM addr 0x" << std::hex << sym_addr << " is outside __TEXT segment\n";
                    break;
                }
                uintptr_t offset = sym_addr - base_vmaddr;
                hello_func = reinterpret_cast<void (*)()>((uint8_t *)mapped_memory + offset);
                // On arm64, functions are 4-byte aligned
                if (reinterpret_cast<uintptr_t>(hello_func) % 4 != 0)
                {
                    std::cerr << "Function pointer for '_hello' at " << (void *)hello_func << " is not 4-byte aligned\n";
                    hello_func = nullptr;
                    break;
                }
                std::cout << "Found 'hello' symbol at VM addr: 0x" << std::hex << sym_addr
                          << ", mem ptr: " << (void *)hello_func << std::dec << "\n";
                break;
            }
        }

        if (hello_func)
        {
            std::cout << "Calling 'hello' function from loaded dylib...\n";
            try
            {
                hello_func();
            }
            catch (...)
            {
                std::cerr << "Exception in hello function\n";
            }
        }
        else
        {
            std::cerr << "Symbol '_hello' not found or invalid in dylib.\n";
        }
    }
    else
    {
        std::cerr << "No LC_SYMTAB command found, cannot locate symbols.\n";
    }

    uintptr_t symbol_addr = find_symbol_address(macho_data.data(), "_hello", base_vmaddr);
    if (symbol_addr == 0)
    {
        std::cerr << "Symbol '_hello' not found.\n";
        munmap(mapped_memory, max_vmaddr - base_vmaddr);
        return 1;
    }

    using func_t = void (*)();
    func_t func = reinterpret_cast<func_t>(reinterpret_cast<uint8_t *>(mapped_memory) + (symbol_addr - base_vmaddr));
    // On arm64, functions are 4-byte aligned
    if (reinterpret_cast<uintptr_t>(func) % 4 != 0)
    {
        std::cerr << "Function pointer for '_hello' at " << (void *)func << " is not 4-byte aligned\n";
        munmap(mapped_memory, max_vmaddr - base_vmaddr);
        return 1;
    }
    if (text_segment && (symbol_addr < text_segment->vmaddr || symbol_addr >= text_segment->vmaddr + text_segment->vmsize))
    {
        std::cerr << "Symbol '_hello' at VM addr 0x" << std::hex << symbol_addr << " is outside __TEXT segment\n";
        munmap(mapped_memory, max_vmaddr - base_vmaddr);
        return 1;
    }
    std::cout << "Calling test function at mem ptr: " << (void *)func << "\n";

    try
    {
        func();
        std::cout << "test function executed successfully\n";
    }
    catch (...)
    {
        std::cerr << "Exception in test function\n";
    }

    munmap(mapped_memory, max_vmaddr - base_vmaddr);
    std::cout << "Mach-O binary loaded and processed successfully.\n";

    return 0;
}