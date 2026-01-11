#pragma once

#include "disassembler.h"
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <functional>

namespace orpheus::analysis {

/**
 * CFGNode - A basic block in the control flow graph
 */
struct CFGNode {
    uint64_t address;           // Start address of block
    uint64_t end_address;       // End address (after last instruction)
    uint32_t size;              // Size in bytes

    std::vector<InstructionInfo> instructions;

    // Graph structure
    std::vector<uint64_t> successors;
    std::vector<uint64_t> predecessors;

    // Block type
    enum class Type {
        Normal,         // Regular code block
        Entry,          // Function entry point
        Exit,           // Return/exit block
        Call,           // Ends with call (fall-through continues)
        ConditionalJump,// Ends with conditional branch
        UnconditionalJump, // Ends with unconditional jump
        Switch          // Jump table dispatch
    };
    Type type = Type::Normal;

    // Layout info (for visualization)
    float x = 0.0f;
    float y = 0.0f;
    float width = 200.0f;
    float height = 100.0f;
    int column = 0;             // For hierarchical layout
    int row = 0;

    // Analysis flags
    bool is_loop_header = false;
    bool is_loop_body = false;

    // Get the terminating instruction
    const InstructionInfo* GetTerminator() const {
        return instructions.empty() ? nullptr : &instructions.back();
    }

    // Check block type based on terminator
    void ClassifyType() {
        if (instructions.empty()) {
            type = Type::Normal;
            return;
        }

        const auto& term = instructions.back();
        if (term.is_ret) {
            type = Type::Exit;
        } else if (term.is_call) {
            type = Type::Call;
        } else if (term.is_jump && term.is_conditional) {
            type = Type::ConditionalJump;
        } else if (term.is_jump && !term.is_conditional) {
            type = Type::UnconditionalJump;
        }
    }
};

/**
 * CFGEdge - An edge in the control flow graph
 */
struct CFGEdge {
    uint64_t from;
    uint64_t to;

    enum class Type {
        FallThrough,    // Sequential execution
        Branch,         // Conditional branch taken
        Unconditional,  // Unconditional jump
        Call,           // Call to another function
        Return          // Return edge (implicit)
    };
    Type type = Type::FallThrough;

    bool is_back_edge = false;  // Loop back edge
};

/**
 * ControlFlowGraph - Complete CFG for a function
 */
struct ControlFlowGraph {
    uint64_t function_address;
    uint64_t function_end;
    std::string function_name;

    std::map<uint64_t, CFGNode> nodes;
    std::vector<CFGEdge> edges;

    // Graph metrics
    uint32_t node_count = 0;
    uint32_t edge_count = 0;
    uint32_t max_depth = 0;
    bool has_loops = false;

    // Get entry node
    CFGNode* GetEntry() {
        auto it = nodes.find(function_address);
        return it != nodes.end() ? &it->second : nullptr;
    }

    // Get node by address
    CFGNode* GetNode(uint64_t addr) {
        auto it = nodes.find(addr);
        return it != nodes.end() ? &it->second : nullptr;
    }
};

/**
 * CFGBuilder - Builds control flow graphs from disassembly
 */
class CFGBuilder {
public:
    using ReadMemoryFn = std::function<std::vector<uint8_t>(uint64_t addr, size_t size)>;

    /**
     * Create CFG builder
     * @param read_memory Function to read process memory
     * @param is_64bit True for x64, false for x86
     */
    CFGBuilder(ReadMemoryFn read_memory, bool is_64bit = true);

    /**
     * Build CFG for a function
     * @param function_addr Entry point of the function
     * @param max_size Maximum bytes to analyze (0 = auto-detect)
     * @return Control flow graph, or empty if analysis failed
     */
    ControlFlowGraph BuildCFG(uint64_t function_addr, size_t max_size = 0);

    /**
     * Build CFG from existing disassembly
     * @param instructions Already disassembled instructions
     * @param function_addr Function entry point
     * @return Control flow graph
     */
    ControlFlowGraph BuildCFGFromInstructions(
        const std::vector<InstructionInfo>& instructions,
        uint64_t function_addr);

    /**
     * Compute layout for visualization
     * @param cfg The CFG to layout
     * @param node_width Width of each node
     * @param node_height Base height per instruction
     * @param h_spacing Horizontal spacing between nodes
     * @param v_spacing Vertical spacing between rows
     */
    void ComputeLayout(ControlFlowGraph& cfg,
                       float node_width = 250.0f,
                       float line_height = 16.0f,
                       float h_spacing = 50.0f,
                       float v_spacing = 30.0f);

private:
    // Analysis helpers
    void IdentifyBlocks(const std::vector<InstructionInfo>& instructions,
                        ControlFlowGraph& cfg);
    void BuildEdges(ControlFlowGraph& cfg);
    void DetectLoops(ControlFlowGraph& cfg);
    void ClassifyBlocks(ControlFlowGraph& cfg);

    // Layout helpers
    void AssignLayers(ControlFlowGraph& cfg);
    void AssignColumns(ControlFlowGraph& cfg);
    void PositionNodes(ControlFlowGraph& cfg,
                       float node_width, float line_height,
                       float h_spacing, float v_spacing);

    ReadMemoryFn read_memory_;
    bool is_64bit_;
};

} // namespace orpheus::analysis
