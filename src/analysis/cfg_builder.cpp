#include "cfg_builder.h"
#include <algorithm>
#include <map>
#include <queue>
#include <set>
#include <stack>

namespace orpheus::analysis {

CFGBuilder::CFGBuilder(ReadMemoryFn read_memory, bool is_64bit)
    : read_memory_(std::move(read_memory))
    , is_64bit_(is_64bit) {
}

ControlFlowGraph CFGBuilder::BuildCFG(uint64_t function_addr, size_t max_size) {
    ControlFlowGraph cfg;
    cfg.function_address = function_addr;

    // Default max size if not specified
    if (max_size == 0) {
        max_size = 0x10000;  // 64KB default
    }

    // Read function bytes
    auto data = read_memory_(function_addr, max_size);
    if (data.empty()) {
        return cfg;
    }

    // Disassemble
    Disassembler disasm(is_64bit_);
    DisassemblyOptions opts;
    opts.max_instructions = 10000;

    auto instructions = disasm.Disassemble(data, function_addr, opts);
    if (instructions.empty()) {
        return cfg;
    }

    return BuildCFGFromInstructions(instructions, function_addr);
}

ControlFlowGraph CFGBuilder::BuildCFGFromInstructions(
    const std::vector<InstructionInfo>& instructions,
    uint64_t function_addr) {

    ControlFlowGraph cfg;
    cfg.function_address = function_addr;

    if (instructions.empty()) {
        return cfg;
    }

    // Build instruction map for quick lookup
    std::map<uint64_t, const InstructionInfo*> instr_map;
    for (const auto& instr : instructions) {
        instr_map[instr.address] = &instr;
    }

    // Find all reachable instructions from entry using worklist
    std::set<uint64_t> reachable;
    std::queue<uint64_t> worklist;
    worklist.push(function_addr);

    while (!worklist.empty()) {
        uint64_t addr = worklist.front();
        worklist.pop();

        if (reachable.count(addr)) continue;

        auto it = instr_map.find(addr);
        if (it == instr_map.end()) continue;

        reachable.insert(addr);
        const auto& instr = *it->second;

        // Stop at returns
        if (instr.is_ret) continue;

        // Add branch target if within function
        if (instr.branch_target) {
            uint64_t target = *instr.branch_target;
            if (instr_map.count(target) && !reachable.count(target)) {
                worklist.push(target);
            }
        }

        // Add fall-through (for non-unconditional jumps and non-rets)
        if (!instr.is_ret && !(instr.is_jump && !instr.is_conditional)) {
            uint64_t next = instr.address + instr.length;
            if (instr_map.count(next) && !reachable.count(next)) {
                worklist.push(next);
            }
        }
    }

    // Filter instructions to only reachable ones
    std::vector<InstructionInfo> reachable_instrs;
    for (const auto& instr : instructions) {
        if (reachable.count(instr.address)) {
            reachable_instrs.push_back(instr);
        }
    }

    if (reachable_instrs.empty()) {
        return cfg;
    }

    // Find function end from reachable instructions
    uint64_t max_addr = 0;
    for (const auto& instr : reachable_instrs) {
        uint64_t end = instr.address + instr.length;
        max_addr = std::max(max_addr, end);
    }
    cfg.function_end = max_addr;

    // Build basic blocks from reachable instructions only
    IdentifyBlocks(reachable_instrs, cfg);

    // Build edges between blocks
    BuildEdges(cfg);

    // Detect loops (back edges)
    DetectLoops(cfg);

    // Classify block types
    ClassifyBlocks(cfg);

    // Update metrics
    cfg.node_count = static_cast<uint32_t>(cfg.nodes.size());
    cfg.edge_count = static_cast<uint32_t>(cfg.edges.size());

    return cfg;
}

void CFGBuilder::IdentifyBlocks(const std::vector<InstructionInfo>& instructions,
                                 ControlFlowGraph& cfg) {
    if (instructions.empty()) return;

    // Find all block start addresses
    std::set<uint64_t> block_starts;
    block_starts.insert(instructions[0].address);  // Entry is always a block start

    for (const auto& instr : instructions) {
        // Instructions after branches start new blocks
        if (instr.is_call || instr.is_jump || instr.is_ret) {
            uint64_t next_addr = instr.address + instr.length;
            if (next_addr <= cfg.function_end) {
                block_starts.insert(next_addr);
            }

            // Branch targets are block starts
            if (instr.branch_target) {
                uint64_t target = *instr.branch_target;
                if (target >= cfg.function_address && target < cfg.function_end) {
                    block_starts.insert(target);
                }
            }
        }
    }

    // Create blocks
    CFGNode* current_block = nullptr;

    for (const auto& instr : instructions) {
        // Start new block if needed
        if (block_starts.count(instr.address) || current_block == nullptr) {
            // Finalize previous block
            if (current_block && !current_block->instructions.empty()) {
                const auto& last = current_block->instructions.back();
                current_block->end_address = last.address + last.length;
                current_block->size = static_cast<uint32_t>(
                    current_block->end_address - current_block->address);
            }

            // Create new block
            cfg.nodes[instr.address] = CFGNode();
            current_block = &cfg.nodes[instr.address];
            current_block->address = instr.address;

            // Mark entry block
            if (instr.address == cfg.function_address) {
                current_block->type = CFGNode::Type::Entry;
            }
        }

        current_block->instructions.push_back(instr);

        // If this is a return, we might want to stop following this path
        if (instr.is_ret) {
            current_block->type = CFGNode::Type::Exit;
        }
    }

    // Finalize last block
    if (current_block && !current_block->instructions.empty()) {
        const auto& last = current_block->instructions.back();
        current_block->end_address = last.address + last.length;
        current_block->size = static_cast<uint32_t>(
            current_block->end_address - current_block->address);
    }
}

void CFGBuilder::BuildEdges(ControlFlowGraph& cfg) {
    for (auto& [addr, node] : cfg.nodes) {
        if (node.instructions.empty()) continue;

        const auto& term = node.instructions.back();

        // Unconditional jump - only successor is target
        if (term.is_jump && !term.is_conditional && !term.is_ret) {
            if (term.branch_target) {
                uint64_t target = *term.branch_target;
                if (cfg.nodes.count(target)) {
                    node.successors.push_back(target);
                    cfg.nodes[target].predecessors.push_back(addr);

                    CFGEdge edge;
                    edge.from = addr;
                    edge.to = target;
                    edge.type = CFGEdge::Type::Unconditional;
                    cfg.edges.push_back(edge);
                }
            }
        }
        // Conditional jump - two successors
        else if (term.is_jump && term.is_conditional) {
            // Fall-through successor
            uint64_t fall_through = node.end_address;
            if (cfg.nodes.count(fall_through)) {
                node.successors.push_back(fall_through);
                cfg.nodes[fall_through].predecessors.push_back(addr);

                CFGEdge edge;
                edge.from = addr;
                edge.to = fall_through;
                edge.type = CFGEdge::Type::FallThrough;
                cfg.edges.push_back(edge);
            }

            // Branch target successor
            if (term.branch_target) {
                uint64_t target = *term.branch_target;
                if (cfg.nodes.count(target)) {
                    node.successors.push_back(target);
                    cfg.nodes[target].predecessors.push_back(addr);

                    CFGEdge edge;
                    edge.from = addr;
                    edge.to = target;
                    edge.type = CFGEdge::Type::Branch;
                    cfg.edges.push_back(edge);
                }
            }
        }
        // Call - fall-through continues
        else if (term.is_call) {
            uint64_t fall_through = node.end_address;
            if (cfg.nodes.count(fall_through)) {
                node.successors.push_back(fall_through);
                cfg.nodes[fall_through].predecessors.push_back(addr);

                CFGEdge edge;
                edge.from = addr;
                edge.to = fall_through;
                edge.type = CFGEdge::Type::FallThrough;
                cfg.edges.push_back(edge);
            }
        }
        // Return - no successors
        else if (term.is_ret) {
            // No successors
        }
        // Normal instruction - fall-through
        else {
            uint64_t fall_through = node.end_address;
            if (cfg.nodes.count(fall_through)) {
                node.successors.push_back(fall_through);
                cfg.nodes[fall_through].predecessors.push_back(addr);

                CFGEdge edge;
                edge.from = addr;
                edge.to = fall_through;
                edge.type = CFGEdge::Type::FallThrough;
                cfg.edges.push_back(edge);
            }
        }
    }
}

void CFGBuilder::DetectLoops(ControlFlowGraph& cfg) {
    // Simple back-edge detection using DFS
    std::set<uint64_t> visited;
    std::set<uint64_t> in_stack;

    std::function<void(uint64_t)> dfs = [&](uint64_t addr) {
        visited.insert(addr);
        in_stack.insert(addr);

        auto it = cfg.nodes.find(addr);
        if (it == cfg.nodes.end()) return;

        for (uint64_t succ : it->second.successors) {
            if (in_stack.count(succ)) {
                // Back edge found - this is a loop
                cfg.has_loops = true;

                // Mark the edge as a back edge
                for (auto& edge : cfg.edges) {
                    if (edge.from == addr && edge.to == succ) {
                        edge.is_back_edge = true;
                    }
                }

                // Mark loop header
                if (cfg.nodes.count(succ)) {
                    cfg.nodes[succ].is_loop_header = true;
                }

                // Mark current node as loop body
                it->second.is_loop_body = true;
            } else if (!visited.count(succ)) {
                dfs(succ);
            }
        }

        in_stack.erase(addr);
    };

    if (!cfg.nodes.empty()) {
        dfs(cfg.function_address);
    }
}

void CFGBuilder::ClassifyBlocks(ControlFlowGraph& cfg) {
    for (auto& [addr, node] : cfg.nodes) {
        node.ClassifyType();

        // Override with Entry for function entry
        if (addr == cfg.function_address) {
            node.type = CFGNode::Type::Entry;
        }
    }
}

void CFGBuilder::ComputeLayout(ControlFlowGraph& cfg,
                                float node_width,
                                float line_height,
                                float h_spacing,
                                float v_spacing) {
    if (cfg.nodes.empty()) return;

    // Assign layers (rows) using BFS from entry
    AssignLayers(cfg);

    // Assign columns to minimize edge crossings
    AssignColumns(cfg);

    // Compute actual positions
    PositionNodes(cfg, node_width, line_height, h_spacing, v_spacing);
}

void CFGBuilder::AssignLayers(ControlFlowGraph& cfg) {
    // BFS from entry to assign layers
    std::map<uint64_t, int> layers;
    std::queue<uint64_t> queue;

    queue.push(cfg.function_address);
    layers[cfg.function_address] = 0;

    int max_layer = 0;

    while (!queue.empty()) {
        uint64_t addr = queue.front();
        queue.pop();

        auto it = cfg.nodes.find(addr);
        if (it == cfg.nodes.end()) continue;

        int current_layer = layers[addr];

        for (uint64_t succ : it->second.successors) {
            // Skip back edges for layer assignment
            bool is_back_edge = false;
            for (const auto& edge : cfg.edges) {
                if (edge.from == addr && edge.to == succ && edge.is_back_edge) {
                    is_back_edge = true;
                    break;
                }
            }
            if (is_back_edge) continue;

            if (!layers.count(succ)) {
                layers[succ] = current_layer + 1;
                max_layer = std::max(max_layer, current_layer + 1);
                queue.push(succ);
            }
        }
    }

    // Apply layers to nodes
    for (auto& [addr, node] : cfg.nodes) {
        node.row = layers.count(addr) ? layers[addr] : 0;
    }

    cfg.max_depth = max_layer + 1;
}

void CFGBuilder::AssignColumns(ControlFlowGraph& cfg) {
    // Group nodes by layer
    std::map<int, std::vector<uint64_t>> layers;
    for (const auto& [addr, node] : cfg.nodes) {
        layers[node.row].push_back(addr);
    }

    // Assign columns within each layer
    for (auto& [layer, addrs] : layers) {
        // Sort by predecessor positions for better layout
        std::sort(addrs.begin(), addrs.end(), [&cfg](uint64_t a, uint64_t b) {
            // Entry node first
            if (a == cfg.function_address) return true;
            if (b == cfg.function_address) return false;

            // Otherwise sort by address
            return a < b;
        });

        int col = 0;
        for (uint64_t addr : addrs) {
            cfg.nodes[addr].column = col++;
        }
    }
}

void CFGBuilder::PositionNodes(ControlFlowGraph& cfg,
                                float node_width,
                                float line_height,
                                float h_spacing,
                                float v_spacing) {
    // Find max columns per row for centering
    std::map<int, int> max_cols;
    for (const auto& [addr, node] : cfg.nodes) {
        max_cols[node.row] = std::max(max_cols[node.row], node.column + 1);
    }

    // Find overall max columns
    int overall_max_cols = 1;
    for (const auto& [row, cols] : max_cols) {
        overall_max_cols = std::max(overall_max_cols, cols);
    }

    float total_width = overall_max_cols * (node_width + h_spacing);

    // Position each node
    float current_y = 0;
    int current_row = 0;
    float row_height = 0;

    // Sort nodes by row for sequential processing
    std::vector<uint64_t> sorted_addrs;
    for (const auto& [addr, _] : cfg.nodes) {
        sorted_addrs.push_back(addr);
    }
    std::sort(sorted_addrs.begin(), sorted_addrs.end(), [&cfg](uint64_t a, uint64_t b) {
        return cfg.nodes[a].row < cfg.nodes[b].row ||
               (cfg.nodes[a].row == cfg.nodes[b].row && cfg.nodes[a].column < cfg.nodes[b].column);
    });

    for (uint64_t addr : sorted_addrs) {
        auto& node = cfg.nodes[addr];

        // Calculate node height based on instruction count
        node.width = node_width;
        node.height = std::max(40.0f, node.instructions.size() * line_height + 20.0f);

        // New row?
        if (node.row != current_row) {
            current_y += row_height + v_spacing;
            current_row = node.row;
            row_height = 0;
        }

        row_height = std::max(row_height, node.height);

        // Center the row
        int cols_in_row = max_cols[node.row];
        float row_width = cols_in_row * (node_width + h_spacing) - h_spacing;
        float row_start_x = (total_width - row_width) / 2.0f;

        node.x = row_start_x + node.column * (node_width + h_spacing);
        node.y = current_y;
    }
}

} // namespace orpheus::analysis
