#pragma once

#include <string>
#include <cstdint>
#include <optional>
#include <functional>
#include <vector>
#include <map>

namespace orpheus::utils {

/**
 * ExpressionEvaluator - Evaluate address expressions
 *
 * Supports:
 * - Raw hex addresses: 0x7FF600001000, 7FF600001000
 * - Module names: client.dll, kernel32.dll
 * - Offsets: client.dll+0x1000, client.dll-0x100
 * - Dereference: [address], [[address]+offset]
 * - Arithmetic: +, -, *, /
 * - Parentheses: (client.dll+0x100)*2
 *
 * Example expressions:
 * - "client.dll"                      -> module base address
 * - "client.dll+0x1234"               -> module base + offset
 * - "[client.dll+0x10]"               -> dereference pointer at module+0x10
 * - "[[client.dll+0x10]+0x20]"        -> nested pointer dereference
 * - "rax"                             -> register value (if register context provided)
 */
class ExpressionEvaluator {
public:
    // Callback to resolve module name to base address
    using ModuleResolver = std::function<std::optional<uint64_t>(const std::string& name)>;

    // Callback to read memory (for dereference)
    using MemoryReader = std::function<std::optional<uint64_t>(uint64_t address)>;

    // Callback to resolve register name to value
    using RegisterResolver = std::function<std::optional<uint64_t>(const std::string& name)>;

    /**
     * Create evaluator
     * @param module_resolver Function to resolve module names to base addresses
     * @param memory_reader Function to read 8-byte value from memory (for dereference)
     * @param register_resolver Optional function to resolve register names
     */
    ExpressionEvaluator(
        ModuleResolver module_resolver,
        MemoryReader memory_reader,
        RegisterResolver register_resolver = nullptr
    );

    /**
     * Evaluate an expression
     * @param expression The expression to evaluate
     * @return The evaluated address, or nullopt if evaluation failed
     */
    std::optional<uint64_t> Evaluate(const std::string& expression);

    /**
     * Get error message from last failed evaluation
     */
    const std::string& GetError() const { return error_; }

    /**
     * Set a named variable for use in expressions
     * @param name Variable name (without $ prefix)
     * @param value Variable value
     */
    void SetVariable(const std::string& name, uint64_t value);

    /**
     * Clear all variables
     */
    void ClearVariables();

private:
    // Token types
    enum class TokenType {
        Number,         // 0x1234, 1234
        Identifier,     // module name, register name
        Plus,           // +
        Minus,          // -
        Star,           // *
        Slash,          // /
        LParen,         // (
        RParen,         // )
        LBracket,       // [
        RBracket,       // ]
        Variable,       // $name
        End
    };

    struct Token {
        TokenType type;
        std::string text;
        uint64_t value = 0;  // For numbers
    };

    // Lexer
    std::vector<Token> Tokenize(const std::string& expr);

    // Parser (recursive descent)
    std::optional<uint64_t> ParseExpression();
    std::optional<uint64_t> ParseTerm();
    std::optional<uint64_t> ParseFactor();
    std::optional<uint64_t> ParsePrimary();
    std::optional<uint64_t> ParseDereference();

    // Helper
    bool Match(TokenType type);
    bool Check(TokenType type) const;
    const Token& Peek() const;
    const Token& Advance();
    bool IsAtEnd() const;

    ModuleResolver module_resolver_;
    MemoryReader memory_reader_;
    RegisterResolver register_resolver_;

    std::vector<Token> tokens_;
    size_t current_ = 0;
    std::string error_;

    std::map<std::string, uint64_t> variables_;
};

} // namespace orpheus::utils
