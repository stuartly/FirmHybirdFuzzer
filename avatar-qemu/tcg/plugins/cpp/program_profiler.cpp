#include "plugin_api.h"

#include "json.hpp"

#include <algorithm>
#include <inttypes.h>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

using json = nlohmann::json;

class basic_block;
using sym_call_stack = std::vector<const symbol*>;
using loop_stack = std::vector<const basic_block*>;

/* statistics associated to one context of execution (symbol, loops, ...) */
class execution_statistics
{
public:
    void context_entered() { ++number_of_times_entered_; }
    void context_repeated() { ++number_of_times_repeated_; }

    void block_was_executed(translation_block& b, uint64_t bytes_read,
                            uint64_t bytes_written)
    {
        instructions_executed_ += b.instructions().size();
        total_bytes_read_ += bytes_read;
        total_bytes_written_ += bytes_written;

        for (auto* inst : b.instructions()) {
            switch (get_instruction_type(*inst)) {
            case instruction_type::MEMORY:
                ++instructions_executed_memory_;
                break;
            case instruction_type::ARITHMETIC_AND_LOGIC:
                ++instructions_executed_arithmetic_and_logic_;
                break;
            case instruction_type::CONTROL:
                ++instructions_executed_control_;
                break;
            }
        }
    }

    void block_was_executed(const execution_statistics& stats)
    {
        *this += stats;
    }

    uint64_t instructions_executed() const { return instructions_executed_; }
    uint64_t instructions_executed_memory() const
    {
        return instructions_executed_memory_;
    }
    uint64_t instructions_executed_control() const
    {
        return instructions_executed_control_;
    }
    uint64_t instructions_executed_arithmetic_and_logic() const
    {
        return instructions_executed_arithmetic_and_logic_;
    }
    uint64_t total_bytes_read() const { return total_bytes_read_; }
    uint64_t total_bytes_written() const { return total_bytes_written_; }
    uint64_t number_of_times_entered() const
    {
        return number_of_times_entered_;
    }
    uint64_t number_of_times_repeated() const
    {
        return number_of_times_repeated_;
    }

    execution_statistics& operator+=(const execution_statistics& rhs)
    {
        instructions_executed_ += rhs.instructions_executed_;
        instructions_executed_control_ += rhs.instructions_executed_control_;
        instructions_executed_arithmetic_and_logic_ +=
            rhs.instructions_executed_arithmetic_and_logic_;
        instructions_executed_memory_ += rhs.instructions_executed_memory_;
        total_bytes_written_ += rhs.total_bytes_written_;
        total_bytes_read_ += rhs.total_bytes_read_;
        number_of_times_entered_ += rhs.number_of_times_entered_;
        number_of_times_repeated_ += rhs.number_of_times_repeated_;
        return *this;
    }

private:
    enum class instruction_type
    {
        MEMORY,
        ARITHMETIC_AND_LOGIC,
        CONTROL
    };

    instruction_type get_instruction_type(const instruction& inst)
    {
        const cs_insn* cap = &inst.capstone_inst();

        /* we classify as memory inst any having one memory operand. In case of
         * x86, most arithmetic instructions can have memory operand, which may
         * results in wrong results. */

        if (insn_is_control(cap))
            return instruction_type::CONTROL;
        else if (insn_has_memory_operand(cap))
            return instruction_type::MEMORY;
        else
            return instruction_type::ARITHMETIC_AND_LOGIC;
    }

    static bool insn_is_control(const cs_insn* insn)
    {
        return insn_is_in_group(insn, CS_GRP_JUMP) ||
               insn_is_in_group(insn, CS_GRP_CALL) ||
               insn_is_in_group(insn, CS_GRP_RET) ||
               insn_is_in_group(insn, CS_GRP_INT) ||
               insn_is_in_group(insn, CS_GRP_IRET);
    }

    static bool insn_is_in_group(const cs_insn* insn, cs_group_type group)
    {
        return cs_insn_group(instruction::get_capstone_handle(), insn, group);
    }

    template <typename arch_details, typename op_type>
    static bool insn_has_memory_operand_arch(const arch_details& details,
                                             op_type mem_type)
    {
        for (size_t i = 0; i < details.op_count; i++) {
            if (details.operands[i].type == mem_type) {
                return true;
            }
        }
        return false;
    }

    static bool insn_has_memory_operand(const cs_insn* insn)
    {
        switch (plugin::get_guest_architecture()) {
        case architecture::ARCHITECTURE_ARM:
            return insn_has_memory_operand_arch(insn->detail->arm, ARM_OP_MEM);
        case architecture::ARCHITECTURE_I386:
        case architecture::ARCHITECTURE_X86_64:
            return insn_has_memory_operand_arch(insn->detail->x86, X86_OP_MEM);
        case architecture::ARCHITECTURE_AARCH64:
            return insn_has_memory_operand_arch(insn->detail->arm64,
                                                ARM64_OP_MEM);
        case architecture::ARCHITECTURE_UNKNOWN:
            return false;
        }
        return false;
    }

    uint64_t instructions_executed_ = 0;
    uint64_t instructions_executed_memory_ = 0;
    uint64_t instructions_executed_arithmetic_and_logic_ = 0;
    uint64_t instructions_executed_control_ = 0;
    uint64_t total_bytes_written_ = 0;
    uint64_t total_bytes_read_ = 0;
    uint64_t number_of_times_entered_ = 0;
    uint64_t number_of_times_repeated_ = 0;
};

/* as opposed to translation_block, basic_block offers guarantee that
 * any of its instructions are not in another basic_block (single entry/exit
 * point). Since a basic_block exists for each beginning of a translation_block,
 * a lot of things are retrieved from it (id, symbols, ...). */
class basic_block
{
public:
    basic_block(translation_block& tb) : tb_(tb), size_(tb_.size()) {}

    uint64_t id() const { return tb_.id(); }
    uint64_t pc() const { return tb_.pc(); }
    size_t size() const { return size_; }
    symbol& current_symbol() const { return *tb_.current_symbol(); }
    const std::unordered_set<symbol*>& symbols() const { return tb_.symbols(); }
    const std::vector<basic_block*>& successors() const { return successors_; }
    basic_block* loop_header() const { return loop_header_; }
    bool is_loop_header() const { return is_loop_header_; }
    std::vector<instruction*> instructions() const
    {
        std::vector<instruction*> res;
        auto start =
            std::find_if(tb_.instructions().begin(), tb_.instructions().end(),
                         [&](instruction* i) { return i->pc() == pc(); });
        uint64_t end_pc = pc() + size();
        auto end =
            std::find_if(start, tb_.instructions().end(),
                         [&](instruction* i) { return i->pc() >= end_pc; });
        res.insert(res.end(), start, end);
        return res;
    }

    /* split current block with @new_bb (successor of current bb) */
    void split_block(basic_block& new_bb)
    {
        basic_block& orig_bb = *this;
        orig_bb.size_ = new_bb.pc() - orig_bb.pc();

        // report block chain
        for (auto* s : orig_bb.successors())
            new_bb.chain_block(*s);
        orig_bb.successors_.clear();
        // chain new block to orig one only
        orig_bb.chain_block(new_bb);

        if (!new_bb.is_loop_header())
            new_bb.loop_header_ = orig_bb.loop_header_;
    }

    bool chain_block(basic_block& succ)
    {
        for (auto* s : successors_) {
            if (s == &succ)
                return false;
        }
        successors_.emplace_back(&succ);
        return true;
    }

    void mark_as_loop_header(bool is_lh) { is_loop_header_ = is_lh; }
    void set_loop_header(basic_block* lh) { loop_header_ = lh; }

private:
    translation_block& tb_;
    size_t size_;
    std::vector<basic_block*> successors_;
    bool is_loop_header_ = false;
    basic_block* loop_header_ = nullptr;
};

/* Loop detection algorithm used is:
 * A New Algorithm for Identifying Loops in Decompilation, by
 * Tao Wei, Jian Mao, Wei Zou, Yu Chen
 * http://lenx.100871.net/papers/loop-SAS.pdf
 */

struct bb_loop_info
{
    basic_block* loop_header = nullptr;
    uint64_t depth_first_search_pos = 0;
    bool visited = false;
};

using bb_loop_infos = std::unordered_map<basic_block*, bb_loop_info>;

static void tag_lhead(basic_block& b, basic_block* h, bb_loop_infos& infos);
static basic_block* trav_loops_dfs(basic_block& b0, uint64_t dfs_pos,
                                   bb_loop_infos& infos);

// procedure identify_loops (CFG G=(N,E,h0)):
//    foreach(Block b in N): // init
//        initialize(b); // zeroize flags & properties
//    trav_loops_DFS(h0,1);
static void identify_loops(basic_block* entry_block)
{
    if (!entry_block)
        return;

    bb_loop_infos infos;
    trav_loops_dfs(*entry_block, 0, infos);

    // reset all blocks
    for (auto& p : infos) {
        basic_block* bb_ptr = p.first;
        bb_ptr->mark_as_loop_header(false);
        bb_ptr->set_loop_header(nullptr);
    }

    // mark new loop header
    for (auto& p : infos) {
        basic_block* bb_ptr = p.first;
        bb_loop_info& info = p.second;
        bb_ptr->set_loop_header(info.loop_header);
        if (info.loop_header)
            info.loop_header->mark_as_loop_header(true);
    }
}

// function trav_loops_DFS (Block b0, int DFSP_pos):
////return: innermost loop header of b0
//    Mark b0 as traversed;
//    b0.DFSP_pos := DFSP_pos;//Mark b0’s position in DFSP
//    foreach (Block b in Succ(b0)):
//        if(b is not traversed):
//            // case(A), new
//            Block nh := trav_loops_DFS(b, DFSP_pos+1);
//            tag_lhead(b0, nh);
//        else:
//            if(b.DFSP_pos > 0): // b in DFSP(b0)
//                // case(B)
//                Mark b as a loop header;
//                tag_lhead(b0, b);
//            else if(b.iloop_header == nil):
//                // case(C), do nothing
//            else:
//                Block h := b.iloop_header;
//                if(h.DFSP_pos > 0): // h in DFSP(b0)
//                    // case(D)
//                    tag_lhead(b0, h);
//                else: // h not in DFSP(b0)
//                    // case(E), reentry
//                    Mark b and (b0,b) as re-entry;
//                    Mark the loop of h as irreducible;
//                    while (h.iloop_header!=nil):
//                        h := h.iloop_header;
//                        if(h.DFSP_pos > 0): // h in DFSP(b0)
//                            tag_lhead(b0, h);
//                            break;
//                        Mark the loop of h as irreducible;
//    b0.DFSP_pos := 0; // clear b0’s DFSP position
//    return b0.iloop_header;
static basic_block* trav_loops_dfs(basic_block& b0, uint64_t dfs_pos,
                                   bb_loop_infos& infos)
{
    bb_loop_info& b0_info = infos[&b0];
    b0_info.visited = true;
    b0_info.depth_first_search_pos = dfs_pos;
    for (basic_block* b : b0.successors()) {
        /* ignore blocks not in this symbol */
        if (&b0.current_symbol() != &b->current_symbol())
            continue;

        bb_loop_info& b_info = infos[b];
        if (!b_info.visited) {
            basic_block* nh = trav_loops_dfs(*b, dfs_pos + 1, infos);
            tag_lhead(b0, nh, infos);
        } else {
            if (b_info.depth_first_search_pos > 0) {
                // mark b as loop header
                tag_lhead(b0, b, infos);
            } else if (!b_info.loop_header) {
                // nothing
            } else {
                basic_block* h = b_info.loop_header;
                bb_loop_info* h_info_ptr = &infos[h];
                if (h_info_ptr->depth_first_search_pos > 0) {
                    tag_lhead(b0, h, infos);
                } else {
                    // Mark b and (b0,b) as re-entry
                    // Mark loop of h as irreducible
                    while (h_info_ptr->loop_header) {
                        h = h_info_ptr->loop_header;
                        h_info_ptr = &infos[h];
                        if (h_info_ptr->depth_first_search_pos > 0) {
                            tag_lhead(b0, h, infos);
                            break;
                        }
                        // Mark the loop of h as irreducible
                    }
                }
            }
        }
    }
    b0_info.depth_first_search_pos = 0;
    return b0_info.loop_header;
}

// procedure tag_lhead (Block b, Block h):
//    if(b == h or h == nil)
//        return;
//    Block cur1 := b, cur2 := h;
//    while (cur1.iloop_header!=nil):
//        Block ih := cur1.iloop_header;
//        if(ih == cur2)
//            return;
//        if(ih.DFSP_pos < cur2.DFSP_pos):
//            cur1.iloop_header := cur2;
//            cur1 := cur2;
//            cur2 := ih;
//        else:
//            cur1 := ih;
//   cur1.iloop_header := cur2;
static void tag_lhead(basic_block& b, basic_block* h, bb_loop_infos& infos)
{
    if (&b == h || !h)
        return;
    basic_block* cur1 = &b;
    basic_block* cur2 = h;
    bb_loop_info* cur1_info_ptr = &infos[cur1];
    while (cur1_info_ptr->loop_header) {
        basic_block* ih = cur1_info_ptr->loop_header;
        if (ih == cur2)
            return;
        bb_loop_info* ih_info_ptr = &infos[ih];
        bb_loop_info* cur2_info_ptr = &infos[cur2];
        if (ih_info_ptr->depth_first_search_pos <
            cur2_info_ptr->depth_first_search_pos) {
            cur1_info_ptr->loop_header = cur2;
            cur1 = cur2;
            cur1_info_ptr = cur2_info_ptr;
            cur2 = ih;
            cur2_info_ptr = ih_info_ptr;
        } else {
            cur1 = ih;
            cur1_info_ptr = ih_info_ptr;
        }
    }
    cur1_info_ptr->loop_header = cur2;
}

template <typename TypeWithId>
static void sort_vec_elem_with_id(std::vector<TypeWithId*>& vec)
{
    std::sort(vec.begin(), vec.end(), [](const auto* e1, const auto* e2) {
        return e1->id() < e2->id();
    });
}

template <typename T>
static std::vector<T*>
get_vec_from_unordered_set(const std::unordered_set<T*>& set)
{
    std::vector<T*> vec;
    vec.reserve(set.size());
    vec.insert(vec.end(), set.begin(), set.end());
    return vec;
}

/* return sources for a vector of @instructions,
 * with a given number lines of @context.
 * Holes between source lines can be added as well. */
static std::vector<const source_line*> get_sorted_sources_from_instructions(
    const std::vector<instruction*>& instructions, uint64_t context_size,
    bool fill_holes)
{
    std::unordered_set<const source_line*> src_set;
    for (auto* i : instructions) {
        const source_line* src = i->line();
        if (!src)
            continue;
        src_set.emplace(src);
    }

    if (context_size || fill_holes) {
        struct bounds
        {
            uint64_t min = std::numeric_limits<uint64_t>::max();
            uint64_t max = std::numeric_limits<uint64_t>::min();
            uint64_t new_min = 0;
            uint64_t new_max = 0;
        };
        std::unordered_map<const source_file*, bounds> src_bounds;

        // accumulate all bounds for files
        for (auto* s : src_set) {
            bounds& b = src_bounds[&s->file()];
            uint64_t line = static_cast<uint64_t>(s->number());
            b.min = std::min(line, b.min);
            b.max = std::max(line, b.max);
        }

        // correct with context size
        for (auto& p : src_bounds) {
            const source_file& f = *p.first;
            bounds& b = p.second;
            b.new_max = std::min(b.max + context_size, f.length());
            if (context_size >= b.min)
                b.new_min = 1;
            else
                b.new_min = b.min - context_size;
        }

        // add missing lines
        for (auto& p : src_bounds) {
            const source_file& f = *p.first;
            bounds& b = p.second;

            // add context lines
            for (uint64_t num = b.new_min; num <= b.min; ++num)
                src_set.emplace(&f.get_line(num));
            for (uint64_t num = b.max; num <= b.new_max; ++num)
                src_set.emplace(&f.get_line(num));

            // fill holes if needed
            if (fill_holes)
                for (uint64_t num = b.min; num <= b.max; ++num)
                    src_set.emplace(&f.get_line(num));
        }
    }

    std::vector<const source_line*> src_vec =
        get_vec_from_unordered_set(src_set);
    std::sort(src_vec.begin(), src_vec.end(),
              [](const auto& l1_ptr, const auto& l2_ptr) {
                  const source_line& l1 = *l1_ptr;
                  const source_line& l2 = *l2_ptr;
                  if (l1.file().path() == l2.file().path())
                      return l1.number() < l2.number();
                  return l1.file().path() < l2.file().path();
              });
    return src_vec;
}

static json json_one_source_line(const source_line* src, bool executed)
{
    json j;
    if (src) {
        j = {{"file", src->file().path()},
             {"line", src->number()},
             {"str", src->line()},
             {"executed", executed}};
    }
    return j;
}

static json json_one_instruction(const instruction& i, bool executed)
{
    // do not report instruction id
    json j_src;
    json j = {{"pc", i.pc()},
              {"size", i.size()},
              {"str", i.str()},
              {"src", json_one_source_line(i.line(), executed)},
              {"executed", executed}};
    return j;
}

static json json_one_block(const basic_block& bb)
{
    json j_succ = json::array();
    auto successors = bb.successors();
    sort_vec_elem_with_id(successors);
    for (auto* succ : successors)
        j_succ.emplace_back(succ->id());

    json j_inst = json::array();
    for (auto* inst : bb.instructions())
        j_inst.emplace_back(json_one_instruction(*inst, true));

    auto src =
        get_sorted_sources_from_instructions(bb.instructions(), 0, false);
    json j_src = json::array();
    for (auto* s : src)
        j_src.emplace_back(json_one_source_line(s, true));

    json j_syms = json::array();
    auto symbols = get_vec_from_unordered_set(bb.symbols());
    sort_vec_elem_with_id(symbols);
    for (auto* s : symbols)
        j_syms.emplace_back(s->id());

    json loop_header;
    if (bb.loop_header())
        loop_header = bb.loop_header()->id();

    json j = {{"id", bb.id()},
              {"pc", bb.pc()},
              {"size", bb.size()},
              {"symbols", j_syms},
              {"instructions", j_inst},
              {"successors", j_succ},
              {"loop_header", loop_header},
              {"src", j_src}};
    return j;
}

static json json_one_statistic(const execution_statistics& stat)
{
    json j = {
        {"instructions_executed", stat.instructions_executed()},
        {"instructions_executed_memory", stat.instructions_executed_memory()},
        {"instructions_executed_arithmetic_and_logic",
         stat.instructions_executed_arithmetic_and_logic()},
        {"instructions_executed_control", stat.instructions_executed_control()},
        {"num_times_entered", stat.number_of_times_entered()},
        {"num_times_repeated", stat.number_of_times_repeated()},
        {"bytes_written", stat.total_bytes_written()},
        {"bytes_read", stat.total_bytes_read()}};
    return j;
}

static json json_one_symbol(
    const symbol& s, std::vector<basic_block*>& sym_blocks,
    const std::vector<instruction*>& instructions,
    const std::unordered_set<symbol*>& calls,
    const std::unordered_set<const source_line*>& covered_source_lines,
    const std::unordered_set<instruction*>& covered_instructions,
    const execution_statistics& stats,
    const execution_statistics& stats_cumulated)
{
    json j_instructions = json::array();
    for (instruction* i : instructions) {
        j_instructions.emplace_back(
            json_one_instruction(*i, covered_instructions.count(i) != 0));
    }

    sort_vec_elem_with_id(sym_blocks);
    json j_blocks = json::array();
    for (const auto& b : sym_blocks)
        j_blocks.emplace_back(b->id());

    auto src = get_sorted_sources_from_instructions(instructions, 3, true);
    json j_src = json::array();
    for (auto* s : src)
        j_src.emplace_back(
            json_one_source_line(s, covered_source_lines.count(s) != 0));

    json j_calls = json::array();
    auto vec_calls = get_vec_from_unordered_set(calls);
    sort_vec_elem_with_id(vec_calls);
    for (const auto* calls : vec_calls) {
        j_calls.emplace_back(calls->id());
    }

    json j_name;
    const std::string& name = s.name();
    if (!name.empty())
        j_name = name;

    json j_file;
    const std::string& file = s.file().path();
    if (!file.empty())
        j_file = file;

    json j = {{"id", s.id()},
              {"pc", s.pc()},
              {"size", s.size()},
              {"file", j_file},
              {"name", j_name},
              {"instructions", j_instructions},
              {"basic_blocks", j_blocks},
              {"calls", j_calls},
              {"src", j_src},
              {"stats", json_one_statistic(stats)},
              {"stats_cumulated", json_one_statistic(stats_cumulated)}};
    return j;
}

static json json_one_loop(const basic_block& loop_header,
                          const execution_statistics& stats,
                          const execution_statistics& stats_cumulated)
{
    json j = {{"loop_header", loop_header.id()},
              {"stats", json_one_statistic(stats)},
              {"stats_cumulated", json_one_statistic(stats_cumulated)}};
    return j;
}

json json_one_call_stack(const sym_call_stack& cs, uint64_t count)
{
    json j_cs = json::array();
    for (auto* s : cs) {
        j_cs.emplace_back(s->id());
    }
    return json{{"symbols", j_cs}, {"count", count}};
}

json json_one_loop_stack(const loop_stack& ls, uint64_t count)
{
    json j_s = json::array();
    for (auto* b : ls) {
        j_s.emplace_back(b->id());
    }
    return json{{"basic_blocks", j_s}, {"count", count}};
}

struct loop_and_call_stack_entry
{
    loop_and_call_stack_entry(bool is_call, basic_block& bb,
                              uint64_t expected_next_pc,
                              execution_statistics& cumulated_stats)
        : is_call(is_call), bb(&bb), orig_sym(&bb.current_symbol()),
          expected_next_pc(expected_next_pc), cumulated_stats(&cumulated_stats)
    {
    }
    bool is_call;     /* if true, it is a loop */
    basic_block* bb;  /* if call, bb that made call, else loop header */
    symbol* orig_sym; /* current symbol for bb at times of entry creation */
    uint64_t expected_next_pc;             /* used for call return address */
    execution_statistics* cumulated_stats; /* stats for context coming from this
                                              one */
};

/* keeps track of stack for loops and functions */
class loop_and_call_stack
{
public:
    symbol* current_symbol() { return current_symbol_; }
    basic_block* current_loop_header() { return current_loop_header_; }

    void on_start(basic_block& bb) { set_current_symbol(&bb.current_symbol()); }

    void on_call(basic_block& bb, basic_block& last)
    {
        // fprintf(stderr, "CALL @0x%" PRIx64 " FROM 0x%" PRIx64 "\n", bb.pc(),
        //        last.current_symbol().pc());
        set_current_symbol(&bb.current_symbol());
        stack_.emplace_back(true, last, last.pc() + last.size(),
                            symbols_stats_cumulated_[&last.current_symbol()]);

        current_symbol_stats_->context_entered();
    }

    void on_return(basic_block& bb)
    {
        /* walk stack back to find where we returned */
        for (auto it = stack_.rbegin(); it != stack_.rend(); ++it) {
            if (it->is_call && bb.pc() == it->expected_next_pc) /* found */
            {
                stack_.erase(it.base() - 1, stack_.end());
                break;
            }
        }

        set_current_symbol(&bb.current_symbol());
        /* find current loop header */
        set_current_loop_header(backtrace_loop_header());
        // fprintf(stderr, "RET IN 0x%" PRIx64 "\n", current_symbol_->pc());
    }

    basic_block* backtrace_loop_header()
    {
        for (auto it = stack_.rbegin(); it != stack_.rend(); ++it)
            if (!it->is_call)
                return it->bb;
        return nullptr;
    }

    void on_transition(basic_block& bb, basic_block& last_bb)
    {
        // fprintf(stderr,
        // "--------------------------------------------------\n");
        // fprintf(stderr, "PREVIOUS BLOCK 0x%" PRIx64 "\n", last_bb.pc());
        // fprintf(stderr, "CURRENT BLOCK 0x%" PRIx64 "\n", bb.pc());
        // fprintf(stderr, "CURRENT BLOCK HEADER @0x%" PRIx64 "\n",
        //        bb.loop_header() ? bb.loop_header()->pc() : 0);
        // fprintf(stderr, "IS LOOP HEADER? %s\n",
        //        bb.is_loop_header() ? "true" : "false");

        if ((last_bb.loop_header() == bb.loop_header()) &&
            !bb.is_loop_header() && !last_bb.is_loop_header()) {
            /* we are still in the same loop iteration (or out of any) */
            return;
        }

        /* we are changing of loop (or iteration) */
        if (last_bb.loop_header() || last_bb.is_loop_header()) {
            /* iterate on loop */
            if (current_loop_header_ == &bb) {
                // fprintf(stderr, "NEW LOOP ITER @0x%" PRIx64 "\n", bb.pc());
                current_loop_header_stats_->context_repeated();
                return;
            }

            if (current_loop_header_ &&
                &current_loop_header_->current_symbol() ==
                    &bb.current_symbol() &&
                current_loop_header_ != bb.loop_header() &&
                current_loop_header_ != &bb) {
                /* exit current loop */
                // fprintf(stderr, "EXIT LOOP @0x%" PRIx64 "\n",
                //        current_loop_header_ ? current_loop_header_->pc() :
                //        0);
                for (auto it = stack_.rbegin(); it != stack_.rend(); ++it) {
                    if (it->is_call)
                        continue;
                    if (it->orig_sym != &bb.current_symbol())
                        break;
                    if (it->bb == current_loop_header_) {
                        stack_.erase(it.base() - 1, stack_.end());
                        break;
                    }
                }
                set_current_loop_header(backtrace_loop_header());
            }
        }

        /* we don't enter in a new loop */
        if (!bb.is_loop_header() && !bb.loop_header())
            return;

        /* we enter in a new loop */
        basic_block* new_loop_header = bb.loop_header();
        if (bb.is_loop_header())
            new_loop_header = &bb;

        if (new_loop_header == current_loop_header_)
            return;

        set_current_loop_header(new_loop_header);
        stack_.emplace_back(false, *current_loop_header_, 0,
                            loops_stats_cumulated_[current_loop_header_]);
        current_loop_header_stats_->context_entered();
        // fprintf(stderr, "ENTER LOOP @0x%" PRIx64 "\n",
        //        current_loop_header_->pc());
    }

    void on_block_executed(translation_block& b,
                           const std::vector<memory_access>& memory_accesses)
    {
        const execution_statistics& block_stats =
            get_stats_for_block(b, memory_accesses);

        total_stats_.block_was_executed(block_stats);

        /* record stats for current block/loop */
        current_symbol_stats_->block_was_executed(block_stats);
        /* current symbol is never pushed on stack, on the opposite of loop
         * stack, thus add stat accumulated */
        current_symbol_stats_cumulated_->block_was_executed(block_stats);
        if (current_loop_header_)
            current_loop_header_stats_->block_was_executed(block_stats);

        /* record cumulated stats for blocks/loops */
        for (auto& e : stack_)
            e.cumulated_stats->block_was_executed(block_stats);

        /* record call stack/loop stack every N samples */
        record_cpu_stacks(b);
        record_memory_stacks(b, block_stats.total_bytes_read(),
                             block_stats.total_bytes_written());
    }

    const std::map<sym_call_stack, uint64_t>& cpu_call_stacks_count() const
    {
        return cpu_call_stacks_count_;
    }

    const std::map<sym_call_stack, uint64_t>& mem_read_call_stacks_count() const
    {
        return mem_read_call_stacks_count_;
    }

    const std::map<sym_call_stack, uint64_t>&
    mem_write_call_stacks_count() const
    {
        return mem_write_call_stacks_count_;
    }

    const std::map<loop_stack, uint64_t>& cpu_loop_stacks_count() const
    {
        return cpu_loop_stacks_count_;
    }

    const std::map<loop_stack, uint64_t>& mem_read_loop_stacks_count() const
    {
        return mem_read_loop_stacks_count_;
    }

    const std::map<loop_stack, uint64_t>& mem_write_loop_stacks_count() const
    {
        return mem_write_loop_stacks_count_;
    }

    const std::unordered_map<symbol*, execution_statistics>&
    symbols_stats() const
    {
        return symbols_stats_;
    }

    const std::unordered_map<basic_block*, execution_statistics>&
    loops_stats() const
    {
        return loops_stats_;
    }

    const execution_statistics& total_statistics() const
    {
        return total_stats_;
    }

    const std::unordered_map<symbol*, execution_statistics>&
    symbols_stats_cumulated() const
    {
        return symbols_stats_cumulated_;
    }

    const std::unordered_map<basic_block*, execution_statistics>&
    loops_stats_cumulated() const
    {
        return loops_stats_cumulated_;
    }

private:
    void record_cpu_stacks(translation_block& b)
    {
        sample_record(b, count_inst_, b.instructions().size(),
                      num_inst_cpu_sample_, [this](translation_block& b) {
                          record_call_stack(b, cpu_call_stacks_count_,
                                            num_inst_cpu_sample_);
                      });
        count_inst_ = sample_record(
            b, count_inst_, b.instructions().size(), num_inst_cpu_sample_,
            [this](translation_block& b) {
                (void)b;
                record_loop_stack(cpu_loop_stacks_count_, num_inst_cpu_sample_);
            });
    }

    void record_memory_stacks(translation_block& b, uint64_t bytes_read,
                              uint64_t bytes_written)
    {
        sample_record(b, count_bytes_read_, bytes_read, num_bytes_mem_sample_,
                      [this](translation_block& b) {
                          record_call_stack(b, mem_read_call_stacks_count_,
                                            num_bytes_mem_sample_);
                      });
        sample_record(b, count_bytes_written_, bytes_written,
                      num_bytes_mem_sample_, [this](translation_block& b) {
                          record_call_stack(b, mem_write_call_stacks_count_,
                                            num_bytes_mem_sample_);
                      });

        count_bytes_read_ =
            sample_record(b, count_bytes_read_, bytes_read,
                          num_bytes_mem_sample_, [this](translation_block& b) {
                              (void)b;
                              record_loop_stack(mem_read_loop_stacks_count_,
                                                num_bytes_mem_sample_);
                          });
        count_bytes_written_ =
            sample_record(b, count_bytes_written_, bytes_written,
                          num_bytes_mem_sample_, [this](translation_block& b) {
                              (void)b;
                              record_loop_stack(mem_write_loop_stacks_count_,
                                                num_bytes_mem_sample_);
                          });
    }

    /* sample a record (with function @f) if needed for current block.
     * return new count */
    template <typename record_sample>
    static uint64_t sample_record(translation_block& b, uint64_t count,
                                  uint64_t current_block_count,
                                  uint64_t sample_size, record_sample&& f)
    {
        unsigned int num_samples = current_block_count / sample_size;
        for (unsigned int i = 0; i < num_samples; ++i)
            f(b);
        current_block_count = current_block_count % sample_size;
        count += current_block_count;
        if (count < sample_size)
            return count;
        count = count % sample_size;
        f(b);
        return count;
    }

    void record_loop_stack(std::map<loop_stack, uint64_t>& map_count,
                           uint64_t sample_size)
    {
        loop_stack loop_s = call_stack_to_loop_stack(stack_);
        map_count[loop_s] += sample_size;
    }

    void record_call_stack(translation_block& b,
                           std::map<sym_call_stack, uint64_t>& map_count,
                           uint64_t sample_size)
    {
        sym_call_stack sym_cs = call_stack_to_sym_call_stack(stack_);
        sym_cs.emplace_back(b.current_symbol());
        map_count[sym_cs] += sample_size;
    }

    static sym_call_stack
    call_stack_to_sym_call_stack(std::vector<loop_and_call_stack_entry>& cs)
    {
        sym_call_stack res;
        res.reserve(cs.size() + 1);
        for (const auto& e : cs) {
            if (!e.is_call)
                continue;
            res.emplace_back(e.orig_sym);
        }
        return res;
    }

    static loop_stack
    call_stack_to_loop_stack(std::vector<loop_and_call_stack_entry>& cs)
    {
        loop_stack res;
        for (const auto& e : cs) {
            if (e.is_call)
                continue;
            res.emplace_back(e.bb);
        }
        return res;
    }

    void set_current_symbol(symbol* s)
    {
        current_symbol_ = s;
        current_symbol_stats_ = &symbols_stats_[s];
        current_symbol_stats_cumulated_ = &symbols_stats_cumulated_[s];
    }

    void set_current_loop_header(basic_block* lh)
    {
        current_loop_header_ = lh;
        current_loop_header_stats_ = nullptr;
        if (current_loop_header_)
            current_loop_header_stats_ = &loops_stats_[lh];
    }

    const execution_statistics&
    get_stats_for_block(translation_block& b,
                        const std::vector<memory_access>& memory_accesses)
    {
        auto it = stat_per_block.find(&b);
        if (it != stat_per_block.end())
            return it->second;

        uint64_t bytes_read = 0;
        uint64_t bytes_written = 0;

        for (auto& m : memory_accesses) {
            if (m.is_load)
                bytes_read += m.size;
            else
                bytes_written += m.size;
        }

        execution_statistics block_stats;
        block_stats.block_was_executed(b, bytes_read, bytes_written);

        return stat_per_block.emplace(&b, block_stats).first->second;
    }

    symbol* current_symbol_ = nullptr;
    execution_statistics* current_symbol_stats_ = nullptr;
    execution_statistics* current_symbol_stats_cumulated_ = nullptr;
    basic_block* current_loop_header_ = nullptr;
    execution_statistics* current_loop_header_stats_ = nullptr;
    std::vector<loop_and_call_stack_entry> stack_;
    std::map<sym_call_stack, uint64_t /* count */> cpu_call_stacks_count_;
    std::map<sym_call_stack, uint64_t /* count */> mem_read_call_stacks_count_;
    std::map<sym_call_stack, uint64_t /* count */> mem_write_call_stacks_count_;
    std::map<loop_stack, uint64_t /* count */> cpu_loop_stacks_count_;
    std::map<loop_stack, uint64_t /* count */> mem_read_loop_stacks_count_;
    std::map<loop_stack, uint64_t /* count */> mem_write_loop_stacks_count_;
    const uint64_t num_inst_cpu_sample_ = 2000;
    const uint64_t num_bytes_mem_sample_ = 1000;
    uint64_t count_inst_ = 0;
    uint64_t count_bytes_read_ = 0;
    uint64_t count_bytes_written_ = 0;
    execution_statistics total_stats_;

    // stats per context + cumulated (when symbol or loop is in loop/call stack)
    std::unordered_map<symbol*, execution_statistics> symbols_stats_;
    std::unordered_map<symbol*, execution_statistics> symbols_stats_cumulated_;
    std::unordered_map<basic_block*, execution_statistics> loops_stats_;
    std::unordered_map<basic_block*, execution_statistics>
        loops_stats_cumulated_;

    /* to avoid recomputing stats at every block exec, we keep it in a map.
     * This implies we consider two execution of the same block results in the
     * same stats. This is almost always true, to the notable exception of
     * conditional load/store. Ignore this for sake of performance. */
    std::unordered_map<translation_block*, execution_statistics> stat_per_block;
};

class plugin_program_profiler : public plugin
{
public:
    plugin_program_profiler()
        : plugin("program_profiler", "profile program "
                                     "and outputs json description for it")
    {
    }

private:
    /* we keep each info per thread */
    loop_and_call_stack& thread_lcs()
    {
        static thread_local loop_and_call_stack& t =
            threads_lcs_[std::this_thread::get_id()];
        return t;
    }

    void on_block_executed(
        translation_block& b,
        const std::vector<memory_access>& memory_accesses) override
    {
        auto& lcs = thread_lcs();
        lcs.on_block_executed(b, memory_accesses);
    }

    void
    on_block_transition(translation_block& next, translation_block* prev,
                        translation_block::block_transition_type type,
                        translation_block* return_original_caller_tb) override
    {
        using tt = translation_block::block_transition_type;

        auto& lcs = thread_lcs();

        /* treat transition */
        switch (type) {
        case tt::START:
            lcs.on_start(get_basic_block(next));
            break;
        case tt::SEQUENTIAL:
        case tt::JUMP: {
            add_transition(*prev, next);
            basic_block& next_bb = get_basic_block(next);
            basic_block& prev_bb = get_basic_block(*prev);
            basic_block& prev_bb_end = get_basic_block_ending(*prev);
            if (prev_bb.pc() != prev_bb_end.pc()) {
                /* simulate all transitions for prev_bb (splitted in several
                 * blocks) */
                auto size = prev->size();
                auto pc = prev->pc();
                basic_block* prev_sub_bb = blocks_map_[pc];
                while (size > prev_sub_bb->size()) {
                    pc += prev_sub_bb->size();
                    size -= prev_sub_bb->size();
                    basic_block* next_sub_bb = blocks_map_[pc];
                    lcs.on_transition(*next_sub_bb, *prev_sub_bb);
                    prev_sub_bb = next_sub_bb;
                }
            }
            // finally add transition from previous to next
            lcs.on_transition(next_bb, prev_bb_end);
        } break;
        case tt::CALL: {
            translation_block& caller_tb = *prev;
            translation_block& callee_tb = next;

            set_as_entry_point(callee_tb);
            add_transition(caller_tb, callee_tb);
            lcs.on_call(get_basic_block(callee_tb),
                        get_basic_block_ending(caller_tb));
        } break;
        case tt::RETURN: {
            translation_block& caller_tb = *return_original_caller_tb;
            // translation_block& callee_tb = *prev;
            translation_block& returned_tb = next;

            add_transition(caller_tb, returned_tb);
            lcs.on_return(get_basic_block(returned_tb));
        } break;
        }
    }

    void set_as_entry_point(translation_block& b)
    {
        symbol& sym = *b.current_symbol();
        basic_block& bb = get_basic_block(b);
        entry_points_[&sym] = &bb;
    }

    void add_transition(translation_block& previous, translation_block& next)
    {
        basic_block& prev_bb_end = get_basic_block_ending(previous);
        basic_block& next_bb_start = get_basic_block(next);
        bool new_trans = prev_bb_end.chain_block(next_bb_start);
        if (new_trans && previous.current_symbol() == next.current_symbol())
            identify_loops(entry_points_[previous.current_symbol()]);
    }

    basic_block& get_basic_block_ending(translation_block& tb)
    {
        basic_block& bb_start = get_basic_block(tb); // may split tb

        if (bb_start.size() == tb.size()) { // tb was not splitted
            return bb_start;
        }

        // tb was splitted
        uint64_t last_pc = tb.pc() + tb.size() - 1;
        basic_block& bb_end = *blocks_map_[last_pc];
        return bb_end;
    }

    /* get or create basic block, automatically split one if necessary. */
    basic_block& get_basic_block(translation_block& tb)
    {
        basic_block* previous_bb = nullptr;
        auto it = blocks_map_.find(tb.pc());
        if (it != blocks_map_.end()) { // a bb already covers this pc
            previous_bb = it->second;
            if (previous_bb->pc() == tb.pc()) // exact mapping
                return *previous_bb;
        }

        // create a new basic block from scratch
        basic_block& new_bb = blocks_
                                  .emplace(std::piecewise_construct,
                                           std::forward_as_tuple(tb.id()),
                                           std::forward_as_tuple(tb))
                                  .first->second;
        // add mapping for new_bb, may split it
        for (uint64_t pc_it = new_bb.pc(); pc_it != new_bb.pc() + new_bb.size();
             ++pc_it) {
            basic_block*& mapped = blocks_map_[pc_it];
            if (mapped == previous_bb) { // jump in the middle of a block
                mapped = &new_bb;
            } else { // jump before a block that already exists
                new_bb.split_block(*mapped);
                break;
            }
        }

        if (previous_bb) {
            // jump in the middle of a block that already exists, split it now
            // potential split of new_bb due to mapped block must be made before
            // this one, to ensure successors blocks are correct (we work from
            // high to low addresses)
            previous_bb->split_block(new_bb);
        }

        return new_bb;
    }

    std::vector<basic_block*> get_vec_blocks()
    {
        std::vector<basic_block*> blocks;
        blocks.reserve(blocks_.size());
        for (auto& p : blocks_) {
            basic_block& bb = p.second;
            blocks.emplace_back(&bb);
        }
        return blocks;
    }

    json json_blocks(std::vector<basic_block*>& blocks) const
    {
        json j = json::array();
        sort_vec_elem_with_id(blocks);

        for (auto* bb_ptr : blocks) {
            const basic_block& bb = *bb_ptr;
            j.emplace_back(json_one_block(bb));
        }

        return j;
    }

    template <typename get_map_from_lcs>
    json json_call_stacks(get_map_from_lcs&& f) const
    {
        json j = json::array();

        std::map<sym_call_stack, uint64_t> call_stacks =
            merge_and_add_maps_from_loop_call_stacks<decltype(call_stacks)>(f);

        for (auto& p : call_stacks) {
            const auto& stack = p.first;
            auto count = p.second;
            j.emplace_back(json_one_call_stack(stack, count));
        }
        return j;
    }

    template <typename get_map_from_lcs>
    json json_loop_stacks(get_map_from_lcs&& f) const
    {
        json j = json::array();

        std::map<loop_stack, uint64_t> loop_stacks =
            merge_and_add_maps_from_loop_call_stacks<decltype(loop_stacks)>(f);

        for (auto& p : loop_stacks) {
            const auto& stack = p.first;
            auto count = p.second;
            j.emplace_back(json_one_loop_stack(stack, count));
        }
        return j;
    }

    json json_statistics() const
    {
        execution_statistics total;
        for (auto& p_thread : threads_lcs_) {
            auto& lcs = p_thread.second;
            total += lcs.total_statistics();
        }

        return json_one_statistic(total);
    }

    json json_symbols(
        std::unordered_map<symbol*, std::unordered_set<basic_block*>>&
            symbols_to_blocks,
        std::unordered_map<symbol*, std::unordered_set<symbol*>>& symbols_calls,
        const std::unordered_set<const source_line*>& covered_source_lines,
        const std::unordered_set<instruction*>& covered_instructions,
        std::unordered_map<symbol*, execution_statistics>& symbols_stats,
        std::unordered_map<symbol*, execution_statistics>&
            symbols_stats_cumulated)
    {
        json j = json::array();

        std::vector<symbol*> symbols;
        symbols.reserve(symbols_to_blocks.size());
        for (const auto& p : symbols_to_blocks)
            symbols.emplace_back(p.first);
        sort_vec_elem_with_id(symbols);

        for (auto* sym_ptr : symbols) {
            symbol& s = *sym_ptr;

            std::vector<basic_block*> sym_blocks =
                get_vec_from_unordered_set(symbols_to_blocks[&s]);

            std::vector<instruction*> instructions;
            if (s.size() != 0 && s.code()) // disassemble whole symbol
            {
                csh handle = instruction::get_capstone_handle();
                instruction::capstone_inst_ptr cs_inst =
                    instruction::get_new_capstone_instruction();
                uint64_t pc = s.pc();
                size_t size = s.size();
                const uint8_t* code = s.code();
                while (
                    cs_disasm_iter(handle, &code, &size, &pc, cs_inst.get())) {
                    uint64_t i_pc = cs_inst->address;
                    instruction& i =
                        plugin::get_instruction(i_pc, std::move(cs_inst));
                    instructions.emplace_back(&i);
                    cs_inst = instruction::get_new_capstone_instruction();
                }
            }

            std::unordered_set<symbol*> calls = symbols_calls[&s];

            execution_statistics& stats = symbols_stats[&s];
            execution_statistics& stats_cumulated = symbols_stats_cumulated[&s];

            j.emplace_back(json_one_symbol(
                s, sym_blocks, instructions, calls, covered_source_lines,
                covered_instructions, stats, stats_cumulated));
        }

        return j;
    }

    json json_loops()
    {
        json j = json::array();

        /* make union of stats for all threads */
        std::unordered_map<basic_block*, execution_statistics> loops_stats =
            merge_and_add_maps_from_loop_call_stacks<decltype(loops_stats)>(
                [](const auto& lcs) { return lcs.loops_stats(); });

        std::unordered_map<basic_block*, execution_statistics>
            loops_stats_cumulated =
                merge_and_add_maps_from_loop_call_stacks<decltype(
                    loops_stats_cumulated)>([](const auto& lcs) {
                    return lcs.loops_stats_cumulated();
                });

        for (auto& p : loops_stats) {
            basic_block& loop_header = *p.first;
            execution_statistics& stats = p.second;
            execution_statistics& cumulated_stats =
                loops_stats_cumulated[&loop_header];

            j.emplace_back(json_one_loop(loop_header, stats, cumulated_stats));
        }

        return j;
    }

    void on_program_end() override
    {
        json j;
        std::vector<basic_block*> blocks = get_vec_blocks();
        j["basic_blocks"] = json_blocks(blocks);

        std::unordered_set<const source_line*> covered_source_lines;
        std::unordered_set<instruction*> covered_instructions;
        std::unordered_map<symbol*, std::unordered_set<basic_block*>>
            symbols_to_blocks;
        std::unordered_map<symbol*, std::unordered_set<symbol*>> symbols_calls;

        for (auto* b : blocks) {
            for (symbol* b_sym : b->symbols()) {
                symbols_to_blocks[b_sym].emplace(b);
                for (auto* succ : b->successors()) {
                    for (symbol* called_sym : succ->symbols()) {
                        if (b_sym == called_sym)
                            continue;
                        symbols_calls[b_sym].emplace(called_sym);
                    }
                }
            }
            for (auto* i : b->instructions())
                covered_instructions.emplace(i);
        }
        for (auto* i : covered_instructions) {
            const source_line* src = i->line();
            if (!src)
                continue;
            covered_source_lines.emplace(src);
        }

        /* make union of stats in all the threads */
        std::unordered_map<symbol*, execution_statistics> symbols_stats =
            merge_and_add_maps_from_loop_call_stacks<decltype(symbols_stats)>(
                [](const auto& lcs) { return lcs.symbols_stats(); });

        std::unordered_map<symbol*, execution_statistics>
            symbols_stats_cumulated =
                merge_and_add_maps_from_loop_call_stacks<decltype(
                    symbols_stats_cumulated)>([](const auto& lcs) {
                    return lcs.symbols_stats_cumulated();
                });

        j["symbols"] = json_symbols(symbols_to_blocks, symbols_calls,
                                    covered_source_lines, covered_instructions,
                                    symbols_stats, symbols_stats_cumulated);

        j["loops"] = json_loops();
        j["cpu_call_stacks"] = json_call_stacks(
            [](const auto& lcs) { return lcs.cpu_call_stacks_count(); });
        j["mem_read_call_stacks"] = json_call_stacks(
            [](const auto& lcs) { return lcs.mem_read_call_stacks_count(); });
        j["mem_write_call_stacks"] = json_call_stacks(
            [](const auto& lcs) { return lcs.mem_write_call_stacks_count(); });
        j["cpu_loop_stacks"] = json_loop_stacks(
            [](const auto& lcs) { return lcs.cpu_loop_stacks_count(); });
        j["mem_read_loop_stacks"] = json_loop_stacks(
            [](const auto& lcs) { return lcs.mem_read_loop_stacks_count(); });
        j["mem_write_loop_stacks"] = json_loop_stacks(
            [](const auto& lcs) { return lcs.mem_write_loop_stacks_count(); });
        j["statistics"] = json_statistics();
        fprintf(output(), "%s\n", j.dump(4, ' ').c_str());
    }

    /* merge and add values from different threads loop and call stack */
    template <class map_type, typename get_map_for_each>
    map_type
    merge_and_add_maps_from_loop_call_stacks(get_map_for_each&& f) const
    {
        map_type res;
        for (auto& p_thread : threads_lcs_) {
            auto& lcs = p_thread.second;
            for (auto& p : f(lcs)) {
                const auto& key = p.first;
                const auto& val = p.second;
                res[key] += val;
            }
        }
        return res;
    }

    std::unordered_map<uint64_t /* id */, basic_block> blocks_;
    std::unordered_map<uint64_t /* pc */, basic_block*> blocks_map_;
    std::unordered_map<symbol*, basic_block*> entry_points_;
    std::unordered_map<std::thread::id, loop_and_call_stack> threads_lcs_;
};

REGISTER_PLUGIN(plugin_program_profiler);
