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

    std::cout << "VM address range found:\n";
    std::cout << "  Base vmaddr: 0x" << std::hex << base_vmaddr << "\n";
    std::cout << "  Max vmaddr:  0x" << std::hex << max_vmaddr << std::dec << "\n";

    return true;
}

// Helper function to align address down to page boundary
uintptr_t page_align_down(uintptr_t addr)
{
    size_t pageSize = getpagesize();
    return addr & ~(pageSize - 1);
}

// Helper function to align address up to page boundary
uintptr_t page_align_up(uintptr_t addr)
{
    size_t pageSize = getpagesize();
    return (addr + pageSize - 1) & ~(pageSize - 1);
}

int map_segments(const struct mach_header_64 *header, const uint8_t *file_data, size_t file_size)
{
    const struct load_command *cmd = (const struct load_command *)(file_data + sizeof(struct mach_header_64));
    const struct load_command *cmds_end = (const struct load_command *)(file_data + header->sizeofcmds + sizeof(struct mach_header_64));

    // Calculate the min and max vmaddr for base address
    uintptr_t min_vmaddr = UINTPTR_MAX;
    uintptr_t max_vmaddr = 0;

    for (const struct load_command *lc = cmd; lc < cmds_end; lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize))
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (seg->vmsize == 0)
                continue;

            if (seg->vmaddr < min_vmaddr)
                min_vmaddr = seg->vmaddr;
            if (seg->vmaddr + seg->vmsize > max_vmaddr)
                max_vmaddr = seg->vmaddr + seg->vmsize;
        }
    }

    if (min_vmaddr == UINTPTR_MAX)
    {
        std::cerr << "No segments found\n";
        return -1;
    }

    // Calculate the full size needed to mmap
    size_t total_vm_size = max_vmaddr - min_vmaddr;
    size_t pageSize = getpagesize();
    uintptr_t aligned_min_vmaddr = page_align_down(min_vmaddr);
    size_t aligned_vm_size = page_align_up(total_vm_size);

    // mmap the whole range first with PROT_NONE
    void *base_addr = mmap(nullptr, aligned_vm_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base_addr == MAP_FAILED)
    {
        perror("mmap base");
        return -1;
    }

    std::cout << "Mapped base at " << base_addr << " size " << aligned_vm_size << "\n";

    // Map each segment content individually inside the reserved area
    for (const struct load_command *lc = cmd; lc < cmds_end; lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize))
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (seg->vmsize == 0)
                continue;

            // Calculate destination address for this segment inside the base mmap
            uintptr_t seg_vmaddr_offset = seg->vmaddr - aligned_min_vmaddr;
            void *seg_addr = (void *)((uintptr_t)base_addr + seg_vmaddr_offset);

            // Copy segment data from file to mapped memory
            if (seg->filesize > 0)
            {
                if (seg->fileoff + seg->filesize > file_size)
                {
                    std::cerr << "Segment filesize out of bounds\n";
                    munmap(base_addr, aligned_vm_size);
                    return -1;
                }
                memcpy(seg_addr, file_data + seg->fileoff, seg->filesize);
            }

            // Zero out remaining bytes if vmsize > filesize
            if (seg->vmsize > seg->filesize)
            {
                memset((void *)((uintptr_t)seg_addr + seg->filesize), 0, seg->vmsize - seg->filesize);
            }

            // Set memory protection per segment's initprot
            int prot = 0;
            if (seg->initprot & VM_PROT_READ)
                prot |= PROT_READ;
            if (seg->initprot & VM_PROT_WRITE)
                prot |= PROT_WRITE;
            if (seg->initprot & VM_PROT_EXECUTE)
                prot |= PROT_EXEC;

            // Align the segment region for mprotect (page aligned)
            uintptr_t prot_start = page_align_down((uintptr_t)seg_addr);
            uintptr_t prot_end = page_align_up((uintptr_t)seg_addr + seg->vmsize);
            size_t prot_size = prot_end - prot_start;

            if (mprotect((void *)prot_start, prot_size, prot) != 0)
            {
                perror("mprotect segment");
                munmap(base_addr, aligned_vm_size);
                return -1;
            }

            std::cout << "Mapped segment " << seg->segname
                      << " at " << seg_addr << " size " << seg->vmsize
                      << " prot=" << prot << "\n";
        }
    }

    // base_addr points to the loaded Mach-O image in memory
    // You can now continue with relocations, bindings, and calling entry points.

    return 0;
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
                      << " file size: 0x" << seg_filesize << std::dec << "\n";

            if (seg_filesize > 0)
            {
                memcpy(dest, src, seg_filesize);
            }

            // Set segment protection flags properly
            int prot = 0;
            if (seg->initprot & VM_PROT_READ)
                prot |= PROT_READ;
            if (seg->initprot & VM_PROT_WRITE)
                prot |= PROT_WRITE;
            if (seg->initprot & VM_PROT_EXECUTE)
                prot |= PROT_EXEC;

            // Align to page size for mprotect
            size_t pagesize = sysconf(_SC_PAGESIZE);
            uintptr_t page_start = reinterpret_cast<uintptr_t>(dest) & ~(pagesize - 1);
            size_t prot_size = ((seg_vmsize + (reinterpret_cast<uintptr_t>(dest) - page_start) + pagesize - 1) & ~(pagesize - 1));

            if (mprotect(reinterpret_cast<void *>(page_start), prot_size, prot) != 0)
            {
                perror("mprotect");
                std::cerr << "Segment mapping failed.\n";
                munmap(mem, size);
                return nullptr;
            }
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    // **After all segment mappings and protections, make entire memory region executable (and readable)**
    /*
    if (mprotect(mem, size, PROT_READ | PROT_EXEC) != 0)
    {
        perror("mprotect PROT_EXEC");
        munmap(mem, size);
        return nullptr;
    }
    */

    return mem;
}

uint64_t read_uleb128(const uint8_t *&p, const uint8_t *end)
{
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
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do
    {
        byte = *p++;
        result |= ((int64_t)(byte & 0x7f)) << bit;
        bit += 7;
    } while (byte & 0x80);

    if ((byte & 0x40) != 0)
    {
        result |= (-1LL) << bit;
    }
    return result;
}

bool perform_rebase(void *base_memory, uint64_t base_vmaddr, const uint8_t *rebase_info, size_t rebase_size)
{
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

        switch (opcode)
        {
        case REBASE_OPCODE_DONE:
            return true;

        case REBASE_OPCODE_SET_TYPE_IMM:
            type = immediate;
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            segment_index = immediate;
            segment_offset = read_uleb128(p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_ULEB:
            segment_offset += read_uleb128(p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            segment_offset += immediate * sizeof(void *);
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            for (int i = 0; i < immediate; i++)
            {
                uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                *target += (uintptr_t)base_memory;
                segment_offset += sizeof(void *);
            }
            break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {
            uint64_t count = read_uleb128(p, end);
            for (uint64_t i = 0; i < count; i++)
            {
                uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                *target += (uintptr_t)base_memory;
                segment_offset += sizeof(void *);
            }
        }
        break;

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {
            uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
            *target += (uintptr_t)base_memory;
            segment_offset += sizeof(void *) + read_uleb128(p, end);
        }
        break;

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {
            uint64_t count = read_uleb128(p, end);
            uint64_t skip = read_uleb128(p, end);
            for (uint64_t i = 0; i < count; i++)
            {
                uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                *target += (uintptr_t)base_memory;
                segment_offset += skip + sizeof(void *);
            }
        }
        break;

        default:
            std::cerr << "Unknown rebase opcode: 0x" << std::hex << (int)opcode << std::dec << "\n";
            return false;
        }
    }
    return true;
}

bool perform_bind(void *base_memory, uint64_t base_vmaddr, const uint8_t *bind_info, size_t bind_size)
{
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
            // Not implemented
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
            // For simplicity, handle only DO_BIND here:
            uintptr_t *target = (uintptr_t *)((uintptr_t)base_memory + segment_offset);

            // Resolve symbol using dlsym in main process (assuming it's loaded)
            void *sym_addr = dlsym(RTLD_DEFAULT, symbol_name.c_str());
            if (!sym_addr)
            {
                std::cerr << "Failed to bind symbol: " << symbol_name << "\n";
                return false;
            }
            // Write address + addend
            *target = (uintptr_t)sym_addr + addend;

            // Advance segment_offset depending on opcode
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
                    uintptr_t *t = (uintptr_t *)((uintptr_t)base_memory + segment_offset);
                    *t = (uintptr_t)dlsym(RTLD_DEFAULT, symbol_name.c_str()) + addend;
                    segment_offset += skip + sizeof(void *);
                }
            }
        }
        break;

        default:
            std::cerr << "Unknown bind opcode: 0x" << std::hex << (int)opcode << std::dec << "\n";
            return false;
        }
    }
    return true;
}

bool run_global_constructors(void *base_memory, uint64_t base_vmaddr, const char *macho_data)
{
    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data);
    const section_64 *init_offsets_section = nullptr;
    const segment_command_64 *text_segment = nullptr;

    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    // Find __TEXT segment and __init_offsets section
    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const segment_command_64 *seg = reinterpret_cast<const segment_command_64 *>(cmd);

            if (strcmp(seg->segname, "__TEXT") == 0)
                text_segment = seg;

            const section_64 *sect = reinterpret_cast<const section_64 *>(seg + 1);

            for (uint32_t j = 0; j < seg->nsects; j++)
            {
                if (strcmp(sect[j].sectname, "__init_offsets") == 0)
                {
                    init_offsets_section = &sect[j];
                    break;
                }
            }
            if (init_offsets_section && text_segment)
                break;
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (!init_offsets_section)
    {
        std::cout << "No __init_offsets section found.\n";
        return false;
    }
    if (!text_segment)
    {
        std::cout << "No __TEXT segment found.\n";
        return false;
    }

    // Calculate pointer to __init_offsets data in memory
    uint64_t section_offset = init_offsets_section->addr - base_vmaddr;

    const uint32_t *offsets = reinterpret_cast<const uint32_t *>((uint8_t *)base_memory + section_offset);
    size_t count = init_offsets_section->size / sizeof(uint32_t);

    // Call each constructor
    for (size_t i = 0; i < count; i++)
    {
        uint64_t func_vmaddr = text_segment->vmaddr + offsets[i];
        uint64_t func_offset_in_mem = func_vmaddr - base_vmaddr;
        void (*ctor)() = reinterpret_cast<void (*)()>((uint8_t *)base_memory + func_offset_in_mem);

        std::cout << "Calling ctor at VM addr: 0x" << std::hex << func_vmaddr
                  << ", mem ptr: " << (void *)ctor << std::dec << "\n";

        ctor();
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
        if (symbol_name == std::string(name + 1)) // skip leading '_'
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

    const struct mach_header_64 *headerx = reinterpret_cast<const struct mach_header_64 *>(macho_data.data());
    const uint8_t *file_datax = reinterpret_cast<const uint8_t *>(macho_data.data());
    size_t file_sizex = macho_data.size();

    int result = map_segments(headerx, file_datax, file_sizex);
    if (result != 0)
    {
        std::cerr << "Mapping failed\n";
        return 1;
    }

    void *mapped_memory = reinterpret_cast<void *>(result);

    /*
    void *mapped_memory = map_segments(macho_data.data(), base_vmaddr, max_vmaddr); // allocate_and_map_segments(macho_data.data(), base_vmaddr, max_vmaddr);
    if (!mapped_memory)
    {
        return 1;
    }
    */

    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(macho_data.data());
    const load_command *cmd = reinterpret_cast<const load_command *>(header + 1);

    const uint8_t *rebase_info = nullptr;
    size_t rebase_size = 0;
    const uint8_t *bind_info = nullptr;
    size_t bind_size = 0;

    // Variables to store symtab info
    const symtab_command *symtab_cmd = nullptr;

    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (cmd->cmd == LC_DYLD_INFO_ONLY)
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
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    if (rebase_info && rebase_size > 0)
    {
        std::cout << "Performing rebase...\n";
        if (!perform_rebase(mapped_memory, base_vmaddr, rebase_info, rebase_size))
        {
            std::cerr << "Rebase failed.\n";
            munmap(mapped_memory, max_vmaddr - base_vmaddr);
            return 1;
        }
    }
    else
    {
        std::cerr << "No rebase info found.\n";
    }

    if (bind_info && bind_size > 0)
    {
        std::cout << "Performing bind...\n";
        if (!perform_bind(mapped_memory, base_vmaddr, bind_info, bind_size))
        {
            std::cerr << "Bind failed.\n";
            munmap(mapped_memory, max_vmaddr - base_vmaddr);
            return 1;
        }
    }
    else
    {
        std::cerr << "No bind info found.\n";
    }

    // Run constructors (__mod_init_func)
    run_global_constructors(mapped_memory, base_vmaddr, macho_data.data());

    // --- New code to lookup and call 'hello' exported symbol ---

    if (symtab_cmd)
    {
        // Get symbol and string tables in the file
        const uint8_t *symtab_ptr = reinterpret_cast<const uint8_t *>(macho_data.data()) + symtab_cmd->symoff;
        const char *strtab_ptr = reinterpret_cast<const char *>(reinterpret_cast<const uint8_t *>(macho_data.data()) + symtab_cmd->stroff);
        uint32_t nsyms = symtab_cmd->nsyms;

        const struct nlist_64 *symbols = reinterpret_cast<const struct nlist_64 *>(symtab_ptr);

        const char *target_symbol = "_hello"; // Mach-O symbols usually have '_' prefix

        void (*hello_func)() = nullptr;

        for (uint32_t i = 0; i < nsyms; ++i)
        {
            const struct nlist_64 &sym = symbols[i];
            if (sym.n_un.n_strx == 0)
                continue; // no name

            const char *name = strtab_ptr + sym.n_un.n_strx;
            if (strcmp(name, target_symbol) == 0)
            {
                // Calculate in-memory function pointer
                uint64_t sym_addr = sym.n_value; // VM address of symbol
                uintptr_t offset = sym_addr - base_vmaddr;

                hello_func = reinterpret_cast<void (*)()>(reinterpret_cast<uint8_t *>(mapped_memory) + offset);
                break;
            }
        }

        if (hello_func)
        {
            std::cout << "Calling 'hello' function from loaded dylib...\n";
            hello_func();
        }
        else
        {
            std::cerr << "Symbol 'hello' not found in dylib.\n";
        }
    }
    else
    {
        std::cerr << "No LC_SYMTAB command found, cannot locate symbols.\n";
    }

    std::cout << "Mach-O binary loaded and rebased/bound in memory.\n";

    uintptr_t symbol_addr = find_symbol_address(macho_data.data(), "_hello", base_vmaddr);
    if (symbol_addr == 0)
    {
        std::cerr << "Symbol not found.\n";
        return 0;
    }

    using func_t = void (*)();

    func_t func = (func_t)((uintptr_t)mapped_memory + (symbol_addr - base_vmaddr));

    func(); // Call the function!

    munmap(mapped_memory, max_vmaddr - base_vmaddr);

    return 0;
}