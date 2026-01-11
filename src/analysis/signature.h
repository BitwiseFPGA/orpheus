#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

namespace orpheus::analysis {

/**
 * SignatureOptions - Configuration for signature generation
 */
struct SignatureOptions {
    bool wildcard_rip_relative = true;    // Wildcard RIP-relative offsets
    bool wildcard_calls = true;           // Wildcard CALL rel32 offsets
    bool wildcard_jumps = true;           // Wildcard JMP rel32 offsets
    bool wildcard_large_immediates = true; // Wildcard 4+ byte immediates
    uint32_t min_unique_bytes = 8;        // Minimum non-wildcarded bytes for uniqueness
    uint32_t max_length = 64;             // Maximum signature length
};

/**
 * SignatureResult - Generated signature with metadata
 */
struct SignatureResult {
    std::string pattern;           // IDA-style pattern (e.g., "48 8B ?? ?? ?? ?? ??")
    std::string pattern_mask;      // x/? mask for each byte
    std::vector<uint8_t> bytes;    // Original bytes
    std::vector<bool> wildcards;   // Which bytes are wildcarded

    uint64_t address;              // Start address
    size_t length;                 // Signature length in bytes
    size_t unique_bytes;           // Number of non-wildcarded bytes
    size_t instruction_count;      // Number of instructions covered

    // Quality metrics
    float uniqueness_ratio;        // unique_bytes / length (higher = better)
    bool is_valid;                 // Has minimum required unique bytes
    std::string error;             // Error message if generation failed
};

/**
 * SignatureGenerator - Create IDA-style byte signatures from code
 *
 * Features:
 * - Automatic wildcard detection for relocatable bytes
 * - RIP-relative offset detection
 * - Call/jump target wildcarding
 * - Quality metrics for signature uniqueness
 */
class SignatureGenerator {
public:
    SignatureGenerator();
    ~SignatureGenerator() = default;

    /**
     * Generate signature from bytes at address
     * @param data Bytes to create signature from
     * @param address Base address of the bytes
     * @param options Signature generation options
     * @return Generated signature with metadata
     */
    SignatureResult Generate(const std::vector<uint8_t>& data,
                            uint64_t address,
                            const SignatureOptions& options = {});

    /**
     * Generate signature from first N instructions
     * @param data Bytes to disassemble
     * @param address Base address
     * @param instruction_count Number of instructions to include
     * @param options Signature generation options
     * @return Generated signature
     */
    SignatureResult GenerateFromInstructions(const std::vector<uint8_t>& data,
                                             uint64_t address,
                                             size_t instruction_count,
                                             const SignatureOptions& options = {});

    /**
     * Format signature in different styles
     */
    static std::string FormatIDA(const SignatureResult& sig);      // "48 8B ?? ?? ?? ??"
    static std::string FormatCode(const SignatureResult& sig);     // "\x48\x8B" with mask
    static std::string FormatCE(const SignatureResult& sig);       // Cheat Engine style

private:
    // Internal structure for tracking instruction byte ranges
    struct ByteRange {
        size_t start;
        size_t length;
        bool should_wildcard;
    };

    // Analyze instruction and determine which bytes to wildcard
    std::vector<ByteRange> AnalyzeInstruction(const uint8_t* data,
                                               size_t size,
                                               uint64_t address,
                                               const SignatureOptions& options);
};

} // namespace orpheus::analysis
