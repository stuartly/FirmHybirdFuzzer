#include "plugin_instrumentation_api.h"

#include "plugin_api.h"

#include <libelfin/dwarf/dwarf++.hh>
#include <libelfin/elf/elf++.hh>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <inttypes.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <unordered_map>

#include <sys/resource.h>
#include <sys/time.h>

// RAII object to use capstone
class capstone
{
public:
    capstone(const capstone&) = delete;
    capstone& operator=(const capstone&) = delete;

    csh handle() const { return handle_; }

    static capstone& get()
    {
        static capstone c;
        return c;
    }

    static void set_guest_architecture(enum architecture arch)
    {
        guest_architecture = arch;
    }

    static enum architecture get_guest_architecture()
    {
        return guest_architecture;
    }

private:
    capstone()
    {
        cs_arch arch = CS_ARCH_X86;
        cs_mode mode = CS_MODE_32;

        switch (guest_architecture) {
        case architecture::ARCHITECTURE_I386:
            arch = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case architecture::ARCHITECTURE_X86_64:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        case architecture::ARCHITECTURE_ARM:
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
        case architecture::ARCHITECTURE_AARCH64:
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_ARM;
            break;
        case architecture::ARCHITECTURE_UNKNOWN:
            fprintf(stderr, "FATAL: capstone architecture was not set\n");
            exit(EXIT_FAILURE);
            break;
        }

        if (cs_open(arch, mode, &handle_) != CS_ERR_OK) {
            fprintf(stderr, "FATAL: error opening capstone library\n");
            exit(EXIT_FAILURE);
        }
        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    ~capstone() { cs_close(&handle_); }

    csh handle_;
    static enum architecture guest_architecture;
};

enum architecture capstone::guest_architecture =
    architecture::ARCHITECTURE_UNKNOWN;

// split a string @str in token delimited by @delim
static std::vector<std::string> split_string(const std::string& str, char delim)
{
    std::stringstream ss(str);
    std::string item;
    std::vector<std::string> res;
    while (std::getline(ss, item, delim)) {
        res.emplace_back(std::move(item));
    }
    return res;
}

csh instruction::get_capstone_handle()
{
    return capstone::get().handle();
}

class call_stack_entry
{
public:
    call_stack_entry(const instruction* caller, uint64_t return_address,
                     translation_block* tb)
        : caller_(caller), return_address_(return_address), tb_(tb)
    {
    }

    const instruction* caller() const { return caller_; }
    uint64_t return_address() const { return return_address_; }
    translation_block* tb() const { return tb_; }

private:
    const instruction* caller_;
    uint64_t return_address_;
    translation_block* tb_;
};

/* keeps track of block execution.
 * maintain a call_stack for all blocks executed.
 * maintain memory accesses for current block.
 * one block_execution_recorder is used per thread.
 * This object is stateful, for current block/thread executing. */
class block_execution_recorder
{
public:
    block_execution_recorder() { call_stack_.reserve(1000); }

    /* report execution of a block @b.
     * @potential_callee_return_address is address where to return in callee. If
     * it matches something we have on the stack, we will detect a call.
     */
    void on_block_exec(translation_block& b,
                       uint64_t potential_callee_return_address)
    {
        last_executed_block_ = current_block_;
        current_block_ = &b;

        memory_accesses_.clear();
        transition_type_ = track_stack(b, potential_callee_return_address);
    }

    /* caller that reached current symbol */
    translation_block* get_caller() const { return caller_; }

    /* how current block was reached */
    translation_block::block_transition_type get_transition_type() const
    {
        return transition_type_;
    }

    translation_block* get_last_block_executed() const
    {
        return last_executed_block_;
    }

    translation_block* get_current_block() const { return current_block_; }

    call_stack get_call_stack() const
    {
        call_stack cs;
        cs.reserve(call_stack_.size() + 1); /* +1 to push current instruction */
        for (const auto& cs_entry : call_stack_)
            cs.emplace_back(cs_entry.caller());
        return cs;
    }

    const std::vector<memory_access>& get_memory_accesses() const
    {
        return memory_accesses_;
    }

    symbol* get_current_symbol() const { return current_symbol_; }

    void add_memory_access(const translation_block& b, uint64_t pc,
                           uint64_t address, uint32_t size, bool is_load)
    {
        if (&b != current_block_) {
            fprintf(stderr, "PLUGIN_CPP: ERROR - reporting memory access for "
                            "unknown block\n");
            exit(EXIT_FAILURE);
        }
        memory_accesses_.emplace_back(pc, address, size, is_load);
    }

private:
    void on_call(symbol& callee, uint64_t return_address)
    {
        caller_ = last_executed_block_;
        current_symbol_ = &callee;
        call_stack_.emplace_back(last_executed_block_->instructions().back(),
                                 return_address, last_executed_block_);
    }

    translation_block::block_transition_type
    track_stack(translation_block& b, uint64_t potential_callee_return_address)
    {
        using tt = translation_block::block_transition_type;

        if (!last_executed_block_) { /* first time */
            current_symbol_ = &plugin::get_symbol(b.pc(), b.file());
            return tt::START;
        }

        uint64_t expected_next_block_pc =
            last_executed_block_->pc() + last_executed_block_->size();

        if (expected_next_block_pc == b.pc()) /* linear execution */
            return tt::SEQUENTIAL;

        // check if current symbol is a symbol entry point
        if (b.current_symbol() && b.current_symbol()->pc() == b.pc()) {
            on_call(*b.current_symbol(), expected_next_block_pc);
            return tt::CALL;
        }

        /* check if we returned, walk the stack to find expected pc */
        for (auto it = call_stack_.rbegin(); it != call_stack_.rend(); ++it) {
            if (it->return_address() == b.pc()) /* this is a function return */
            {
                caller_ = it->tb();
                current_symbol_ = caller_->current_symbol();
                call_stack_.erase(it.base() - 1, call_stack_.end());
                return tt::RETURN;
            }
        }

        if (expected_next_block_pc != potential_callee_return_address) {
            /* this is a simple jump */
            return tt::JUMP;
        }

        /* this is a call, because return address was stored */
        on_call(plugin::get_symbol(b.pc(), b.file()), expected_next_block_pc);
        return tt::CALL;
    }

    std::vector<memory_access> memory_accesses_;
    std::vector<call_stack_entry> call_stack_;
    translation_block* last_executed_block_ = nullptr;
    translation_block* current_block_ = nullptr;
    symbol* current_symbol_ = nullptr;
    translation_block* caller_ = nullptr;
    translation_block::block_transition_type transition_type_ =
        translation_block::block_transition_type::START;
};

// manager for plugins
class plugin_manager
{
public:
    plugin_manager(const plugin_manager&) = delete;
    plugin_manager& operator=(const plugin_manager&) = delete;

    static plugin_manager& get()
    {
        static plugin_manager p;
        return p;
    }

    // get or create a translation block
    translation_block&
    get_translation_block(uint64_t pc, const uint8_t* code, size_t size,
                          const std::string& binary_file_path,
                          uint64_t binary_file_load_address)
    {
        std::lock_guard<std::mutex> mt_lock(mt_mutex_);

        auto it = blocks_mapping_.find(pc);
        if (it != blocks_mapping_.end()) {
            return *it->second;
        }

        uint64_t new_id = block_id_;
        ++block_id_;

        binary_file& file =
            get_binary_file(binary_file_path, binary_file_load_address);

        translation_block& b =
            blocks_
                .emplace(std::piecewise_construct,
                         std::forward_as_tuple(new_id),
                         std::forward_as_tuple(new_id, pc, size, code, file))
                .first->second;

        blocks_mapping_.emplace(pc, &b);
        // add instructions for block
        disassemble_block(b, pc, code, size);

        return b;
    }

    // get or create an instruction
    instruction& get_instruction(uint64_t pc,
                                 instruction::capstone_inst_ptr capstone_inst)
    {
        auto it = instructions_mapping_.find(pc);
        if (it != instructions_mapping_.end()) {
            return *it->second;
        }

        uint64_t new_id = instruction_id_;
        ++instruction_id_;

        instruction& inst =
            instructions_
                .emplace(std::piecewise_construct,
                         std::forward_as_tuple(new_id),
                         std::forward_as_tuple(new_id, std::move(capstone_inst),
                                               pc_to_lines_[pc]))
                .first->second;
        instructions_mapping_.emplace(pc, &inst);
        return inst;
    }

    call_stack get_call_stack()
    {
        return get_current_thread_be().get_call_stack();
    }

    // register plugin @p as available
    void register_plugin(plugin& p)
    {
        const auto& it = available_plugins_.emplace(p.name(), &p);
        if (!it.second) {
            fprintf(stderr_out_, "FATAL: plugin %s was already registered\n",
                    p.name().c_str());
            exit(EXIT_FAILURE);
        }
    }

    void event_program_start()
    {
        activate_plugins();

        for (const auto& p : plugins_) {
            p->on_program_start();
        }
    }

    void event_block_enter(translation_block& b,
                           uint64_t potential_callee_return_address)
    {
        std::lock_guard<std::mutex> mt_lock(mt_mutex_);

        /* report previous block. By reporting only now, we can record memory
         * access and other information that are only available during
         * execution.  */
        block_execution_recorder& be_recorder = get_current_thread_be();
        block_was_executed(be_recorder);

        /* now we handle next block */

        /* check if block is not entry to a known one */
        if (!b.current_symbol()) {
            symbol* existing = get_existing_symbol(b.pc());
            if (existing)
                b.set_current_symbol(*existing);
        }

        /* maintain call stack and detect call/ret */
        be_recorder.on_block_exec(b, potential_callee_return_address);

        /* correct symbol by using call stack */
        b.set_current_symbol(*be_recorder.get_current_symbol());

        /* set symbol code if this block is the entry point */
        if (b.current_symbol()->pc() == b.pc())
            b.current_symbol()->set_code(b.code());
    }

    /* access to memory. lockless event. */
    void event_memory_access(translation_block& b, uint64_t pc,
                             uint64_t address, uint32_t size, bool is_load)
    {
        get_current_thread_be().add_memory_access(b, pc, address, size,
                                                  is_load);
    }

    void event_cpus_stopped()
    {
        // report last block executed, that was exit */
        block_was_executed(get_current_thread_be());

        fprintf(stderr_out_, "PLUGIN_CPP: event_cpus_stopped\n");
        for (const auto& p : plugins_) {
            p->on_program_end();
        }

        print_memory_cpu_stats();
    }

    FILE* get_output() const { return out_; }
    void set_output(FILE* out) { out_ = out; }

    // get or create a symbol (adds it to its file)
    symbol& get_symbol(const std::string& name, uint64_t pc, size_t size,
                       const uint8_t* code, binary_file& file)
    {
        auto it = symbols_mapping_.find(pc);
        if (it != symbols_mapping_.end()) {
            return *it->second;
        }

        uint64_t new_id = symbol_id_;
        ++symbol_id_;

        symbol& s =
            symbols_
                .emplace(
                    std::piecewise_construct, std::forward_as_tuple(new_id),
                    std::forward_as_tuple(new_id, name, pc, size, code, file))
                .first->second;
        symbols_mapping_.emplace(pc, &s);
        file.add_symbol(s);
        return s;
    }

    void print_memory_cpu_stats()
    {
        /* print some statistics */
        struct rusage usage;
        std::memset(&usage, 0, sizeof(struct rusage));
        getrusage(RUSAGE_SELF, &usage);

        float user_time =
            usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.f;
        float sys_time =
            usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.f;

        fprintf(stderr_out_, "PLUGIN_CPP: memory usage: %luMB\n",
                usage.ru_maxrss / 1024);
        fprintf(stderr_out_, "PLUGIN_CPP: cpu user usage: %.2fs\n", user_time);
        fprintf(stderr_out_, "PLUGIN_CPP: cpu system usage: %.2fs\n", sys_time);
        fflush(stderr_out_);
    }

private:
    plugin_manager() {}

    block_execution_recorder& get_current_thread_be()
    {
        static thread_local block_execution_recorder& bc =
            be_recorders_[std::this_thread::get_id()];
        return bc;
    }

    // called after block was executed
    void block_was_executed(const block_execution_recorder& be)
    {
        translation_block* current = be.get_current_block();
        if (!current) /* no block was executed */
            return;

        translation_block& b = *current;
        /* block transition */
        for (const auto& p : plugins_) {
            p->on_block_transition(b, be.get_last_block_executed(),
                                   be.get_transition_type(), be.get_caller());
        }

        /* block execution */
        const auto& mem_accesses = be.get_memory_accesses();
        for (const auto& p : plugins_) {
            p->on_block_executed(b, mem_accesses);
        }
    }

    // get or create a binary file
    binary_file& get_binary_file(const std::string& path, uint64_t load_address)
    {
        auto it = binary_files_.find(path);
        if (it != binary_files_.end()) {
            return it->second;
        }

        binary_file& file = binary_files_.emplace(path, path).first->second;

        std::string error;
        if (!path.empty()) {
            fprintf(stderr_out_, "PLUGIN_CPP: read ELF/DWARF for %s... ",
                    path.c_str());
            fflush(stderr_out_);
            if (!read_elf(file, load_address, error)) {
                fprintf(stderr_out_,
                        "PLUGIN_CPP: WARNING - error reading ELF for "
                        "file %s: %s\n",
                        path.c_str(), error.c_str());
            } else if (!ignore_dwarf_ &&
                       !read_dwarf(path, load_address, error)) {
                fprintf(stderr_out_,
                        "PLUGIN_CPP: WARNING - error reading DWARF "
                        "for file %s: %s\n",
                        path.c_str(), error.c_str());
            }
            fprintf(stderr_out_, "done\n");
            fflush(stderr_out_);
        }

        return file;
    }

    // get or create a source file
    source_file& get_source_file(const std::string& path)
    {
        auto it = source_files_.find(path);
        if (it != source_files_.end())
            return it->second;
        source_file& file = source_files_.emplace(path, path).first->second;
        return file;
    }

    // returns existing symbol @pc
    symbol* get_existing_symbol(uint64_t pc)
    {
        auto it = symbols_mapping_.find(pc);
        if (it != symbols_mapping_.end())
            return it->second;
        return nullptr;
    }

    // disassemble instructions of a given block @b and and them to it
    void disassemble_block(translation_block& b, uint64_t pc,
                           const uint8_t* code, size_t size)
    {
        instruction::capstone_inst_ptr insn =
            instruction::get_new_capstone_instruction();
        csh handle = capstone::get().handle();
        while (cs_disasm_iter(handle, &code, &size, &pc, insn.get())) {
            uint64_t i_pc = insn->address;
            instruction& inst = get_instruction(i_pc, std::move(insn));
            b.add_instruction(inst);
            insn = instruction::get_new_capstone_instruction();
        }
    }

    struct dwarf_entry
    {
        dwarf_entry(uint64_t pc, const source_line* src) : pc(pc), src(src) {}
        uint64_t pc;
        const source_line* src;
        bool operator<(const dwarf_entry& o) const { return pc < o.pc; }
    };

    void read_dwarf_table(const std::vector<dwarf_entry>& lt,
                          dwarf::taddr low_pc, dwarf::taddr high_pc,
                          uint64_t load_address)
    {
        dwarf::taddr last_line_pc = low_pc;
        const source_line* last_src = nullptr;

        // register pc found from @line_pc to @current_pc with @src
        auto save_line = [load_address, this](const source_line* src,
                                              dwarf::taddr line_pc,
                                              dwarf::taddr current_pc) {
            if (!src)
                return;
            for (dwarf::taddr pc = line_pc; pc < current_pc; ++pc)
                pc_to_lines_[pc + load_address] = src;
        };

        // we start from first line that is beyond low_pc
        auto to_find = dwarf_entry(low_pc, nullptr);
        auto first = std::lower_bound(lt.begin(), lt.end(), to_find);

        for (auto it = first; it != lt.end(); ++it) {
            auto e = *it;
            dwarf::taddr current_pc = e.pc;
            const source_line& src = *e.src;

            if (current_pc >= high_pc) // not after
                break;

            save_line(last_src, last_line_pc, current_pc);

            // get src that match current address
            last_line_pc = current_pc;
            last_src = &src;
        }
        // register all last lines until high_pc
        save_line(last_src, last_line_pc, high_pc);
    }

    // return a sorted vector of dwarf_entry for @lt
    // Allow fast lookup to find a pc_range start
    std::vector<dwarf_entry> read_line_table(const dwarf::line_table& lt)
    {
        std::vector<dwarf_entry> res;
        for (auto& e : lt) {
            source_file& file = get_source_file(e.file->path);
            uint64_t lineno = e.line;
            const source_line& src = file.get_line(lineno);
            res.emplace_back(e.address, &src);
        }
        std::sort(res.begin(), res.end());
        return res;
    }

    /* read dwarf file @file loaded at @load_address */
    bool read_dwarf(const std::string& file, uint64_t load_address,
                    std::string& error)
    {
        int fd = open(file.c_str(), O_RDONLY);
        if (fd < 0) {
            error = strerror(errno);
            return false;
        }

        try {
            elf::elf ef(elf::create_mmap_loader(fd));
            dwarf::dwarf dw(dwarf::elf::create_loader(ef));
            for (auto cu : dw.compilation_units()) {
                try {
                    auto lt = read_line_table(cu.get_line_table());
                    auto pc_ranges = dwarf::die_pc_range(cu.root());
                    for (auto& range : pc_ranges) {
                        dwarf::taddr low = range.low;
                        dwarf::taddr high = range.high;
                        read_dwarf_table(lt, low, high, load_address);
                    }
                } catch (dwarf::format_error& exc) {
                    fprintf(stderr_out_,
                            "PLUGIN_CPP: WARNING - error reading DWARF "
                            "for compilation unit at offset 0x%" PRIx64 "\n",
                            cu.get_section_offset());
                    continue;
                } catch (std::out_of_range& exc) {
                    if (std::string(exc.what()) !=
                        "DIE does not have attribute DW_AT_low_pc")
                        throw;
                }
            }
        } catch (dwarf::format_error& exc) {
            if (std::string(exc.what()) ==
                "required .debug_info section missing")
                return true;
            throw;
        }

        return true;
    }

    bool read_elf(binary_file& file, uint64_t load_address, std::string& error)
    {
        int fd = open(file.path().c_str(), O_RDONLY);
        if (fd < 0) {
            error = strerror(errno);
            return false;
        }

        elf::elf f(elf::create_mmap_loader(fd));
        for (auto& sec : f.sections()) {
            if (sec.get_hdr().type != elf::sht::symtab &&
                sec.get_hdr().type != elf::sht::dynsym)
                continue;

            for (auto sym : sec.as_symtab()) {
                auto& d = sym.get_data();
                if (d.type() != elf::stt::func) // ignore non func
                    continue;
                if (d.shnxd == elf::enums::shn::undef) // ignore undef syms
                    continue;
                std::string name = sym.get_name();
                uint64_t pc = d.value + load_address;
                uint64_t size = d.size;
                const uint8_t* code = nullptr;
                symbol& s = get_symbol(name, pc, size, code, file);
                (void)s;
            }
        }

        return true;
    }

    void list_available_plugins()
    {
        fprintf(stderr_out_, "plugins available are:\n");
        for (const auto& pair : available_plugins_) {
            const plugin& p = *pair.second;
            fprintf(stderr_out_, "- %s: %s\n", p.name().c_str(),
                    p.description().c_str());
        }
        fprintf(stderr_out_, "\n");
        fprintf(stderr_out_,
                "you can ignore DWARF info by setting env var %s\n",
                env_var_ignore_dwarf_.c_str());
    }

    void activate_plugins()
    {
        ignore_dwarf_ = getenv(env_var_ignore_dwarf_.c_str()) != nullptr;
        if (ignore_dwarf_)
            fprintf(stderr_out_, "PLUGIN_CPP: ignoring dwarf infos");

        const char* plugins_list_str = getenv(env_var_plugins_name_.c_str());

        if (!plugins_list_str) {
            fprintf(stderr_out_,
                    "FATAL: env var %s must be set to list of active "
                    "plugins (comma separated)\n",
                    env_var_plugins_name_.c_str());
            list_available_plugins();
            exit(EXIT_FAILURE);
        }

        std::vector<std::string> plugins_list_vec =
            split_string(plugins_list_str, ',');
        std::set<std::string> plugins_list(plugins_list_vec.begin(),
                                           plugins_list_vec.end());

        for (const auto& name : plugins_list) {
            const auto& it = available_plugins_.find(name);
            if (it == available_plugins_.end()) {
                fprintf(stderr_out_, "FATAL: plugin %s is unknown\n",
                        name.c_str());
                list_available_plugins();
                exit(EXIT_FAILURE);
            }
            plugins_.push_back(it->second);
        }
    }

    // duplicate stderr to avoid problems with programs closing their
    // standard in/out
    FILE* stderr_out_ = fdopen(dup(fileno(stderr)), "a");
    FILE* out_ = stderr_out_;

    uint64_t instruction_id_ = 0;
    uint64_t block_id_ = 0;
    uint64_t symbol_id_ = 0;
    std::unordered_map<uint64_t /* id */, instruction> instructions_;
    std::unordered_map<uint64_t /* id */, translation_block> blocks_;
    std::unordered_map<uint64_t /* id */, symbol> symbols_;
    std::unordered_map<uint64_t /* pc */, instruction*> instructions_mapping_;
    std::unordered_map<uint64_t /* pc */, translation_block*> blocks_mapping_;
    std::unordered_map<uint64_t /* pc */, symbol*> symbols_mapping_;

    std::unordered_map<std::string /* name */, binary_file> binary_files_;
    std::unordered_map<std::string /* path */, source_file> source_files_;
    std::unordered_map<uint64_t /* pc */, const source_line*> pc_to_lines_;
    std::map<std::string /* name */, plugin*> available_plugins_;
    std::vector<plugin*> plugins_; /* active */
    static const std::string env_var_ignore_dwarf_;
    static const std::string env_var_plugins_name_;
    bool ignore_dwarf_ = false;
    std::unordered_map<std::thread::id, block_execution_recorder> be_recorders_;
    std::mutex mt_mutex_;
};

instruction::capstone_inst_ptr instruction::get_new_capstone_instruction()
{
    instruction::capstone_inst_ptr insn(
        cs_malloc(capstone::get().handle()),
        [](cs_insn* inst) { cs_free(inst, 1); });
    return insn;
}

std::vector<memory_access> plugin::memory_accesses_for_instruction(
    const instruction& i, const std::vector<memory_access>& memory_accesses)
{
    std::vector<memory_access> inst_accesses;
    std::copy_if(memory_accesses.begin(), memory_accesses.end(),
                 std::back_inserter(inst_accesses),
                 [&i](const auto& m) { return m.pc == i.pc(); });
    return inst_accesses;
}

symbol& plugin::get_symbol(uint64_t pc, binary_file& file)
{
    return plugin_manager::get().get_symbol("", pc, 0, nullptr, file);
}

instruction&
plugin::get_instruction(uint64_t pc,
                        instruction::capstone_inst_ptr capstone_inst)
{
    return plugin_manager::get().get_instruction(pc, std::move(capstone_inst));
}

call_stack plugin::get_call_stack()
{
    return plugin_manager::get().get_call_stack();
}

FILE* plugin::output()
{
    return plugin_manager::get().get_output();
}

enum architecture plugin::get_guest_architecture()
{
    return capstone::get_guest_architecture();
}

const std::string plugin_manager::env_var_plugins_name_ = "PLUGIN_CPP";
const std::string plugin_manager::env_var_ignore_dwarf_ =
    "PLUGIN_CPP_IGNORE_DWARF";

void plugin_init(FILE* out, enum architecture arch)
{
    plugin_manager::get().set_output(out);
    capstone::set_guest_architecture(arch);
    plugin_manager::get().event_program_start();
}

void plugin_close()
{
    fflush(plugin_manager::get().get_output());
}

translation_block* get_translation_block(uint64_t pc, const uint8_t* code,
                                         size_t size,
                                         const char* binary_file_path,
                                         uint64_t binary_file_load_address)
{
    translation_block& b = plugin_manager::get().get_translation_block(
        pc, code, size, binary_file_path ? binary_file_path : "",
        binary_file_load_address);
    return &b;
}

void event_block_enter(translation_block* b,
                       uint64_t potential_callee_return_address)
{
    plugin_manager::get().event_block_enter(*b,
                                            potential_callee_return_address);
}

void event_memory_access(translation_block* b, uint64_t pc, uint64_t address,
                         uint32_t size, bool is_load)
{
    plugin_manager::get().event_memory_access(*b, pc, address, size, is_load);
}

void event_cpus_stopped(void)
{
    plugin_manager::get().event_cpus_stopped();
}

void register_plugin(plugin& p)
{
    plugin_manager::get().register_plugin(p);
}
