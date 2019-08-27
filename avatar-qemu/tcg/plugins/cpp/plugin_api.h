#pragma once

#include "plugin_instrumentation_api.h"

#include <capstone/capstone.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

class source_file;
class binary_file;
class translation_block;

/* represent access (from a given @pc) to @address of @size bytes.
 * If @is_load, it is a load, else, it is a store. */
class memory_access
{
public:
    memory_access(uint64_t pc, uint64_t address, uint32_t size, bool is_load)
        : pc(pc), address(address), size(size), is_load(is_load)
    {
    }
    const uint64_t pc;
    const uint64_t address;
    const uint32_t size;
    const bool is_load;
};

class source_line
{
public:
    source_line(unsigned int number, const std::string& line, source_file& file)
        : number_(number), line_(line), file_(file)
    {
    }

    unsigned int number() const { return number_; }
    const std::string& line() const { return line_; }
    source_file& file() const { return file_; }

private:
    unsigned int number_;
    const std::string line_;
    source_file& file_;
};

class source_file
{
public:
    source_file(const std::string& path) : path_(path)
    {
        source_file& file = *this;
        // empty first line
        lines_.emplace_back(0, "", file);

        std::ifstream in(path);
        std::string line;
        unsigned int line_number = 1;
        while (std::getline(in, line)) {
            lines_.emplace_back(line_number, line, file);
            ++line_number;
        }
    }
    const std::string& path() const { return path_; }

    uint64_t length() const { return lines_.size() - 1; }

    // return empty if number is more than number of lines in file or 0
    const source_line& get_line(unsigned int number) const
    {
        if (number > length())
            return lines_[0];
        return lines_[number];
    }

private:
    const std::string path_;
    std::vector<source_line> lines_;
};

// a symbol in binary @file with given @name, at address @pc, @size bytes, with
// @code
class symbol
{
public:
    symbol(uint64_t id, const std::string& name, uint64_t pc, size_t size,
           const uint8_t* code, binary_file& file)
        : id_(id), name_(name), pc_(pc), size_(size), code_(code), file_(file)
    {
    }

    uint64_t id() const { return id_; }
    const std::string& name() const { return name_; }
    uint64_t pc() const { return pc_; }
    size_t size() const { return size_; }
    const uint8_t* code() const { return code_; }
    binary_file& file() const { return file_; }

    void set_code(const uint8_t* code) { code_ = code; }

private:
    uint64_t id_;
    std::string name_;
    uint64_t pc_;
    size_t size_;
    const uint8_t* code_;
    binary_file& file_;
};

// a binary file at @path references several symbols
class binary_file
{
public:
    binary_file(const std::string& path) : path_(path) {}

    void add_symbol(symbol& s) { symbols_.emplace_back(&s); }

    const std::string& path() const { return path_; }
    const std::vector<symbol*>& symbols() const { return symbols_; }

private:
    std::string path_;
    std::vector<symbol*> symbols_;
};

// a single instruction in the program, one per pc
class instruction
{
public:
    using capstone_inst_ptr = std::unique_ptr<cs_insn, void (*)(cs_insn*)>;

    instruction(uint64_t id, capstone_inst_ptr capstone_inst,
                const source_line* line)
        : id_(id), current_symbol_(nullptr),
          capstone_inst_(std::move(capstone_inst)), line_(line)
    {
    }

    uint64_t id() const { return id_; }
    symbol* current_symbol() const { return current_symbol_; }
    uint64_t pc() const { return capstone_inst().address; }
    const std::string str() const
    {
        return capstone_inst().mnemonic + std::string(" ") +
               capstone_inst().op_str;
    }
    size_t size() const { return capstone_inst().size; }
    const cs_insn& capstone_inst() const { return *capstone_inst_; }
    const source_line* line() const { return line_; }
    void set_current_symbol(symbol& symbol) { current_symbol_ = &symbol; }

    static csh get_capstone_handle();
    // allocate a new capstone instruction
    static capstone_inst_ptr get_new_capstone_instruction();

private:
    uint64_t id_;
    symbol* current_symbol_;
    capstone_inst_ptr capstone_inst_;
    const source_line* line_;
};

// a sequence of instruction without any branching
// different from a basic block (no single entry point)
// two translation_block may contains the same set of instructions (one of the
// blocks overlaps on the other)
// When a block is translated, it may not have a symbol yet.
// When it is executed, symbol found from call stack is reported to be its
// current one. Thus, you can always safely assume current_symbol is never NULL.
class translation_block
{
public:
    enum class block_transition_type
    {
        START,      /* program start */
        SEQUENTIAL, /* execute sequentially code */
        JUMP,       /* jump to a different block (no call) */
        CALL,       /* call new function */
        RETURN      /* return from call */
    };

    translation_block(uint64_t id, uint64_t pc, size_t size,
                      const uint8_t* code, binary_file& file)
        : id_(id), pc_(pc), size_(size), code_(code), file_(file),
          current_symbol_(nullptr)
    {
    }

    uint64_t id() const { return id_; }
    uint64_t pc() const { return pc_; }
    size_t size() const { return size_; }
    const uint8_t* code() const { return code_; }
    binary_file& file() const { return file_; }
    symbol* current_symbol() const { return current_symbol_; }
    const std::unordered_set<symbol*>& symbols() const { return symbols_; }
    const std::vector<instruction*>& instructions() const
    {
        return instructions_;
    }
    void set_current_symbol(symbol& symbol)
    {
        if (current_symbol_ == &symbol)
            return;

        current_symbol_ = &symbol;
        symbols_.emplace(current_symbol_);
        for (instruction* i : instructions_) {
            i->set_current_symbol(symbol);
        }
    }

    void add_instruction(instruction& i) { instructions_.emplace_back(&i); }

private:
    uint64_t id_;
    uint64_t pc_;
    size_t size_;
    const uint8_t* code_;
    binary_file& file_;
    symbol* current_symbol_;
    std::unordered_set<symbol*> symbols_;
    std::vector<instruction*> instructions_;
};

using call_stack = std::vector<const instruction*>;

// interface for a plugin (interesting event functions must be overrided)
// instruction and translation_block references remains valid/the same all along
// program execution, thus their addresses can be used as identifiers.
class plugin
{
public:
    plugin(const std::string& name, const std::string& description)
        : name_(name), description_(description)
    {
    }
    virtual ~plugin() {}
    virtual void on_program_start() {}

    /* called for each block transition
     * if type is RETURN, @return_original_caller_tb is set to tb that was used
     * to call this function.
     * if type is START, @prev is null. */
    virtual void
    on_block_transition(translation_block& next, translation_block* prev,
                        translation_block::block_transition_type type,
                        translation_block* return_original_caller_tb)
    {
        (void)next;
        (void)prev;
        (void)type;
        (void)return_original_caller_tb;
    }

    /* called for each block executed (after on_block_transition).
     * Block was executed, and memory access made are @memory_accesses. This
     * vector contains all accesses for this block. */
    virtual void
    on_block_executed(translation_block&,
                      const std::vector<memory_access>& memory_accesses)
    {
        (void)memory_accesses;
    }
    virtual void on_program_end() {}

    const std::string& name() const { return name_; }
    const std::string& description() const { return description_; }

    // return memory access only for a single instruction
    static std::vector<memory_access> memory_accesses_for_instruction(
        const instruction& i,
        const std::vector<memory_access>& memory_accesses);

    // get or create symbol @pc in @file
    static symbol& get_symbol(uint64_t pc, binary_file& file);

    // return guest architecture
    static enum architecture get_guest_architecture();

protected:
    // output stream
    static FILE* output();
    // get or create an instruction
    static instruction&
    get_instruction(uint64_t pc, instruction::capstone_inst_ptr capstone_inst);
    /* return current call_stack. Current instruction is not included,
     * only all callers that lead to current stack */
    static call_stack get_call_stack();

private:
    const std::string name_;
    const std::string description_;
};

// macro to register a plugin from @class_name
#define REGISTER_PLUGIN(class_name)                                            \
    static bool register_##class_name()                                        \
    {                                                                          \
        static class_name plugin;                                              \
        register_plugin(plugin);                                               \
        return true;                                                           \
    }                                                                          \
    static bool register_##class_name##_ = register_##class_name()

// function to register an existing plugin
void register_plugin(plugin& p);
