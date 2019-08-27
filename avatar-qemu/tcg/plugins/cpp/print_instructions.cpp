#include "plugin_api.h"

#include <inttypes.h>

class plugin_print_instructions : public plugin
{
public:
    plugin_print_instructions()
        : plugin("print_instructions",
                 "print instructions block by block when executing")
    {
    }

    void on_program_start() override { fprintf(output(), "start program\n"); }

    void on_block_transition(translation_block& b, translation_block*,
                             translation_block::block_transition_type type,
                             translation_block*) override
    {
        fprintf(output(), "-----------------------------------\n");
        if (!b.current_symbol()->name().empty())
            fprintf(output(), "from symbol '%s' in file '%s'\n",
                    b.current_symbol()->name().c_str(),
                    b.current_symbol()->file().path().c_str());
        fprintf(output(), "block enter 0x%" PRIx64 "\n", b.pc());
        fprintf(output(), "block has %lu instructions\n",
                b.instructions().size());

        using tt = translation_block::block_transition_type;
        switch (type) {
        case tt::START:
            fprintf(output(), "reached by program start\n");
            break;
        case tt::CALL:
            fprintf(output(), "reached by call\n");
            break;
        case tt::RETURN:
            fprintf(output(), "reached by return\n");
            break;
        case tt::SEQUENTIAL:
            fprintf(output(), "reached by sequential execution\n");
            break;
        case tt::JUMP:
            fprintf(output(), "reached by jump\n");
            break;
        }
    }

    void on_instruction_exec(instruction& i,
                             const std::vector<memory_access>& memory_accesses)
    {
        fprintf(output(), "exec 0x%" PRIx64 " %s\n", i.pc(), i.str().c_str());
        const source_line* line = i.line();
        if (line) {
            fprintf(output(), "// from file %s:%u:%s\n",
                    line->file().path().c_str(), line->number(),
                    line->line().c_str());
        }
        for (auto& m : memory_accesses)
            fprintf(output(), "%s %u bytes @%" PRIx64 "\n",
                    m.is_load ? "load" : "store", m.size, m.address);
    }

    void on_block_executed(
        translation_block& b,
        const std::vector<memory_access>& memory_accesses) override
    {
        for (auto* i : b.instructions()) {
            on_instruction_exec(
                *i, memory_accesses_for_instruction(*i, memory_accesses));
        }
        fprintf(output(), "block exit 0x%" PRIx64 "\n", b.pc());
    }

    void on_program_end() override { fprintf(output(), "end program\n"); }

private:
};

REGISTER_PLUGIN(plugin_print_instructions);
