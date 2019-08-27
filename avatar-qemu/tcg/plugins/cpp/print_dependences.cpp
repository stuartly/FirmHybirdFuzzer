#include "plugin_api.h"

#include <array>
#include <capstone/capstone.h>
#include <inttypes.h>
#include <limits>
#include <sstream>
#include <unordered_map>

class plugin_print_dependences : public plugin
{
public:
    plugin_print_dependences()
        : plugin("print_dependences",
                 "print dependences between instructions when executing")
    {
        /* NOTE: this plugin could be implemented much more efficiently:
         * - cache result of cs_regs to only ask capstone once
         * - cache register names
         * - cache string print of an instruction
         *
         * ... but, that's not the point here. */
    }

private:
    using dyn_inst = std::pair<uint64_t /* id */, instruction*>;
    using shadow_memory = std::unordered_map<uint64_t /* addr */, dyn_inst>;
    using shadow_registers =
        std::array<dyn_inst, std::numeric_limits<uint16_t>::max() + 1>;

    dyn_inst* get_register_producer_for(uint16_t reg_id)
    {
        dyn_inst* res = &shadow_registers_[reg_id];
        if (res->first == 0)
            return nullptr;
        return res;
    }

    dyn_inst* get_memory_producer_for(uint64_t address)
    {
        auto it = shadow_mem_.find(address);
        if (it != shadow_mem_.end())
            return &it->second;
        return nullptr;
    }

    void set_register_producer(uint16_t reg_id, instruction& i, uint64_t id)
    {
        shadow_registers_[reg_id] = std::make_pair(id, &i);
    }

    void set_memory_producer(uint64_t address, uint32_t size, instruction& inst,
                             uint64_t id)
    {
        for (unsigned int i = 0; i < size; ++i)
            shadow_mem_[address + i] = std::make_pair(id, &inst);
    }

    std::string get_instruction_print(const instruction& inst, bool show_pc,
                                      uint64_t id)
    {
        std::stringstream ss;
        ss << id << ": ";
        if (show_pc)
            ss << "@0x" << std::hex << inst.pc() << std::dec;
        ss << " " << inst.str();
        if (inst.line())
            ss << " //" << inst.line()->line();
        return ss.str();
    }

    std::string get_instruction_print(const dyn_inst& inst)
    {
        return get_instruction_print(*inst.second, false, inst.first);
    }

    void on_instruction_exec(instruction& inst,
                             const std::vector<memory_access>& memory_accesses)
    {
        uint64_t id = instruction_num_;
        ++instruction_num_;

        fprintf(output(), "------------------------------------------------\n");
        fprintf(output(), "inst_%s\n",
                get_instruction_print(inst, true, id).c_str());
/* cs_regs is only available in capstone next (4.X) */
#if CS_API_MAJOR > 3
        csh handle = instruction::get_capstone_handle();
        cs_regs regs_read, regs_write;
        uint8_t read_count, write_count;
        if (cs_regs_access(handle, &inst.capstone_inst(), regs_read,
                           &read_count, regs_write, &write_count) == 0) {
            for (uint8_t i = 0; i < read_count; i++) {
                uint16_t reg_id = regs_read[i];
                const char* reg_name = cs_reg_name(handle, reg_id);

                std::string producer;
                dyn_inst* dyn = get_register_producer_for(reg_id);
                if (dyn)
                    producer = " - produced by " + get_instruction_print(*dyn);
                fprintf(output(), "reg R: %s%s\n", reg_name, producer.c_str());
            }
            for (uint8_t i = 0; i < write_count; i++) {
                uint16_t reg_id = regs_write[i];
                const char* reg_name = cs_reg_name(handle, reg_id);
                fprintf(output(), "reg W: %s\n", reg_name);
                set_register_producer(reg_id, inst, id);
            }
        }
#else
        fprintf(output(), "NO_REG_INFO: capstone version is too old\n");
#endif

        for (const auto& m : memory_accesses) {
            if (m.is_load) {
                dyn_inst* last = nullptr;
                std::string producer = " - produced by ";
                for (uint32_t i = 0; i < m.size; ++i) {
                    dyn_inst* dyn = get_memory_producer_for(m.address + i);
                    if (!dyn || (last && (dyn->first == last->first)))
                        continue;
                    if (last)
                        producer += " AND ";
                    producer += get_instruction_print(*dyn);
                    last = dyn;
                }
                if (!last)
                    producer = "";

                fprintf(output(), "mem R: %uB@%" PRIx64 "%s\n", m.size,
                        m.address, producer.c_str());
            } else {
                fprintf(output(), "mem W: %uB@%" PRIx64 "\n", m.size,
                        m.address);
                set_memory_producer(m.address, m.size, inst, id);
            }
        }
    }

    void on_block_executed(
        translation_block& b,
        const std::vector<memory_access>& memory_accesses) override
    {
        for (auto* i : b.instructions()) {
            on_instruction_exec(
                *i, memory_accesses_for_instruction(*i, memory_accesses));
        }
    }

    uint64_t instruction_num_ = 1;
    shadow_memory shadow_mem_;
    shadow_registers shadow_registers_;
};

REGISTER_PLUGIN(plugin_print_dependences);
