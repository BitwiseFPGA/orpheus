#include "signature.h"
#include <Zydis/Zydis.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace orpheus::analysis {

SignatureGenerator::SignatureGenerator() = default;

std::vector<SignatureGenerator::ByteRange> SignatureGenerator::AnalyzeInstruction(
    const uint8_t* data,
    size_t size,
    uint64_t address,
    const SignatureOptions& options) {

    std::vector<ByteRange> ranges;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, size, &instruction, operands))) {
        // Invalid instruction - keep all bytes
        ranges.push_back({0, std::min(size, size_t(1)), false});
        return ranges;
    }

    // Start with all bytes as non-wildcarded
    std::vector<bool> wildcard_map(instruction.length, false);

    // Check for RIP-relative memory operands
    if (options.wildcard_rip_relative) {
        for (size_t i = 0; i < instruction.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                // RIP-relative - wildcard the displacement
                if (instruction.raw.disp.size > 0) {
                    size_t disp_offset = instruction.raw.disp.offset;
                    size_t disp_size = instruction.raw.disp.size / 8; // bits to bytes
                    for (size_t j = 0; j < disp_size && (disp_offset + j) < instruction.length; j++) {
                        wildcard_map[disp_offset + j] = true;
                    }
                }
            }
        }
    }

    // Check for relative call/jump
    bool is_relative_branch = false;
    if ((options.wildcard_calls && instruction.meta.category == ZYDIS_CATEGORY_CALL) ||
        (options.wildcard_jumps && (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                                    instruction.meta.category == ZYDIS_CATEGORY_COND_BR))) {

        for (size_t i = 0; i < instruction.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operands[i].imm.is_relative) {
                is_relative_branch = true;
                // Wildcard the immediate (relative offset)
                if (instruction.raw.imm[0].size > 0) {
                    size_t imm_offset = instruction.raw.imm[0].offset;
                    size_t imm_size = instruction.raw.imm[0].size / 8;
                    for (size_t j = 0; j < imm_size && (imm_offset + j) < instruction.length; j++) {
                        wildcard_map[imm_offset + j] = true;
                    }
                }
                break;
            }
        }
    }

    // Check for large immediates that might be addresses
    if (options.wildcard_large_immediates && !is_relative_branch) {
        for (size_t i = 0; i < instruction.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                // Wildcard 4-byte or larger immediates (likely addresses or offsets)
                size_t imm_size = instruction.raw.imm[0].size / 8;
                if (imm_size >= 4) {
                    size_t imm_offset = instruction.raw.imm[0].offset;
                    for (size_t j = 0; j < imm_size && (imm_offset + j) < instruction.length; j++) {
                        wildcard_map[imm_offset + j] = true;
                    }
                }
                break;
            }
        }
    }

    // Also check displacement for non-RIP memory operands (could be stack-relative with large offset)
    // We don't wildcard small stack offsets, but large displacements might be variable
    for (size_t i = 0; i < instruction.operand_count; i++) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base != ZYDIS_REGISTER_RIP) {
            // Check if displacement is large (might be a global offset)
            if (instruction.raw.disp.size >= 32) { // 4 bytes or more
                int64_t disp_val = operands[i].mem.disp.value;
                // If displacement looks like a large value (not small stack offset), consider wildcarding
                // Stack offsets are usually small negatives or positives
                if (disp_val > 0x1000 || disp_val < -0x1000) {
                    size_t disp_offset = instruction.raw.disp.offset;
                    size_t disp_size = instruction.raw.disp.size / 8;
                    for (size_t j = 0; j < disp_size && (disp_offset + j) < instruction.length; j++) {
                        wildcard_map[disp_offset + j] = true;
                    }
                }
            }
        }
    }

    // Convert wildcard map to ranges
    size_t i = 0;
    while (i < instruction.length) {
        ByteRange range;
        range.start = i;
        range.should_wildcard = wildcard_map[i];

        // Extend range while same wildcard status
        while (i < instruction.length && wildcard_map[i] == range.should_wildcard) {
            i++;
        }
        range.length = i - range.start;
        ranges.push_back(range);
    }

    return ranges;
}

SignatureResult SignatureGenerator::Generate(const std::vector<uint8_t>& data,
                                             uint64_t address,
                                             const SignatureOptions& options) {
    SignatureResult result;
    result.address = address;
    result.is_valid = false;

    if (data.empty()) {
        result.error = "No data provided";
        return result;
    }

    // Limit to max_length
    size_t sig_length = std::min(data.size(), static_cast<size_t>(options.max_length));

    result.bytes.assign(data.begin(), data.begin() + sig_length);
    result.wildcards.resize(sig_length, false);
    result.instruction_count = 0;

    // Disassemble and analyze each instruction
    size_t offset = 0;
    while (offset < sig_length) {
        auto ranges = AnalyzeInstruction(data.data() + offset,
                                         sig_length - offset,
                                         address + offset,
                                         options);

        // Apply wildcard decisions
        for (const auto& range : ranges) {
            for (size_t i = 0; i < range.length && (offset + range.start + i) < sig_length; i++) {
                result.wildcards[offset + range.start + i] = range.should_wildcard;
            }
        }

        // Calculate instruction length
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisDecodedInstruction instruction;

        if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr,
                                                        data.data() + offset,
                                                        sig_length - offset,
                                                        &instruction))) {
            offset += instruction.length;
            result.instruction_count++;
        } else {
            offset++; // Skip invalid byte
        }
    }

    result.length = sig_length;

    // Count unique (non-wildcarded) bytes
    result.unique_bytes = 0;
    for (size_t i = 0; i < result.wildcards.size(); i++) {
        if (!result.wildcards[i]) {
            result.unique_bytes++;
        }
    }

    // Calculate quality metrics
    result.uniqueness_ratio = result.length > 0 ?
        static_cast<float>(result.unique_bytes) / result.length : 0.0f;

    result.is_valid = result.unique_bytes >= options.min_unique_bytes;

    // Generate pattern string
    result.pattern = FormatIDA(result);
    result.pattern_mask = "";
    for (bool wc : result.wildcards) {
        result.pattern_mask += wc ? '?' : 'x';
    }

    return result;
}

SignatureResult SignatureGenerator::GenerateFromInstructions(const std::vector<uint8_t>& data,
                                                             uint64_t address,
                                                             size_t instruction_count,
                                                             const SignatureOptions& options) {
    // First, figure out how many bytes N instructions take
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    size_t total_bytes = 0;
    size_t count = 0;
    size_t offset = 0;

    while (offset < data.size() && count < instruction_count) {
        ZydisDecodedInstruction instruction;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, nullptr,
                                                        data.data() + offset,
                                                        data.size() - offset,
                                                        &instruction))) {
            offset += instruction.length;
            count++;
        } else {
            offset++;
        }
    }

    total_bytes = offset;

    // Now generate signature for those bytes
    std::vector<uint8_t> subset(data.begin(), data.begin() + std::min(total_bytes, data.size()));

    SignatureOptions modified_options = options;
    modified_options.max_length = static_cast<uint32_t>(total_bytes);

    return Generate(subset, address, modified_options);
}

std::string SignatureGenerator::FormatIDA(const SignatureResult& sig) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');

    for (size_t i = 0; i < sig.bytes.size(); i++) {
        if (i > 0) ss << " ";

        if (sig.wildcards[i]) {
            ss << "??";
        } else {
            ss << std::setw(2) << static_cast<int>(sig.bytes[i]);
        }
    }

    return ss.str();
}

std::string SignatureGenerator::FormatCode(const SignatureResult& sig) {
    std::stringstream ss;

    // Pattern bytes
    ss << "// Pattern: " << sig.pattern << "\n";
    ss << "const char pattern[] = \"";
    for (uint8_t b : sig.bytes) {
        ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    ss << "\";\n";

    // Mask
    ss << "const char mask[] = \"" << sig.pattern_mask << "\";";

    return ss.str();
}

std::string SignatureGenerator::FormatCE(const SignatureResult& sig) {
    // Cheat Engine uses same format as IDA but with * for wildcards sometimes
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');

    for (size_t i = 0; i < sig.bytes.size(); i++) {
        if (i > 0) ss << " ";

        if (sig.wildcards[i]) {
            ss << "**";
        } else {
            ss << std::setw(2) << static_cast<int>(sig.bytes[i]);
        }
    }

    return ss.str();
}

} // namespace orpheus::analysis
