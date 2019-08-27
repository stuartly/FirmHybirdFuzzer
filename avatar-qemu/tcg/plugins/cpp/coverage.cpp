#include "plugin_api.h"

#include <algorithm>
#include <inttypes.h>
#include <map>
#include <unordered_map>
#include <unordered_set>

class plugin_coverage : public plugin
{
public:
    plugin_coverage()
        : plugin("coverage", "print instructions coverage for known symbols")
    {
    }

    void on_block_executed(translation_block& b,
                           const std::vector<memory_access>&) override
    {
        symbol& s = *b.current_symbol();
        if (s.name().empty())
            return;
        ++blocks_[&b];
        symbols_.insert(&s);
    }

    void on_program_end() override
    {
        /* create a map, that, for each instruction, count number of hits */
        std::unordered_map<uint64_t /* pc */, uint64_t /* counter */> hits;
        for (const auto& pair : blocks_) {
            translation_block& b = *(pair.first);
            uint64_t number_hits = pair.second;
            for (const auto& i : b.instructions()) {
                hits[i->pc()] += number_hits;
            }
        }

        /* create ordered map (pc) of symbols */
        std::map<uint64_t /* pc */, symbol*> ordered_symbols;
        for (const auto& s : symbols_) {
            ordered_symbols[s->pc()] = s;
        }

        /* dump symbol */
        for (const auto& pair : ordered_symbols) {
            symbol& s = *pair.second;
            dump_symbol_coverage(s, hits);
        }
    }

    void dump_symbol_coverage(
        symbol& s,
        std::unordered_map<uint64_t /* pc */, uint64_t /* counter */>& hits)
    {
        csh handle = instruction::get_capstone_handle();
        instruction::capstone_inst_ptr cs_inst =
            instruction::get_new_capstone_instruction();

        uint64_t pc = s.pc();
        size_t size = s.size();
        const uint8_t* code = s.code();

        fprintf(output(), "symbol '%s' from file '%s'\n", s.name().c_str(),
                s.file().path().c_str());
        const source_line* prev_line = nullptr;
        std::unordered_map<const source_line*, uint64_t /* count */>
            source_hits;

        const char* green = "\033[1;32m";
        const char* black = "\033[1;30m";
        const char* white = "\033[1;37m";

        // disassemble whole symbol
        while (cs_disasm_iter(handle, &code, &size, &pc, cs_inst.get())) {
            uint64_t i_pc = cs_inst->address;
            const instruction& i = get_instruction(i_pc, std::move(cs_inst));
            uint64_t count = hits[i.pc()];
            const source_line* line = i.line();
            std::string source;
            if (line && line != prev_line) {
                source = line->file().path() + ":" +
                         std::to_string(line->number()) + " " + line->line();
                source_hits[line] = count;
            }
            prev_line = line;

            if (!source.empty()) {
                fprintf(stderr, "%s\n", source.c_str());
            }
            fprintf(stderr, "%s%8" PRIu64 "%s | 0x%" PRIx64 ":\t%s%s%s\n",
                    count ? green : black, count, black, i.pc(),
                    count ? green : black, i.str().c_str(), white);
            cs_inst = instruction::get_new_capstone_instruction();
        }
        fprintf(output(), "--------------------------------------------\n");
        if (!source_hits.empty()) {
            std::vector<std::pair<const source_line*, uint64_t>> lines;
            lines.insert(lines.end(), source_hits.begin(), source_hits.end());
            std::sort(lines.begin(), lines.end(),
                      [](const auto& p1, const auto& p2) {
                          const source_line& l1 = *p1.first;
                          const source_line& l2 = *p2.first;
                          if (l1.file().path() == l2.file().path())
                              return l1.number() < l2.number();
                          return l1.file().path() < l2.file().path();
                      });
            for (const auto& p : lines) {
                const source_line& l = *p.first;
                uint64_t count = p.second;
                fprintf(stderr, "%s%s:%u\t%s%12" PRIu64 "| %s%s\n", black,
                        l.file().path().c_str(), l.number(),
                        count ? green : black, count, l.line().c_str(), white);
            }
        }
    }

private:
    std::unordered_map<translation_block*, uint64_t /* counter */> blocks_;
    std::unordered_set<symbol*> symbols_;
};

REGISTER_PLUGIN(plugin_coverage);
