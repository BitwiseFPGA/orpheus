#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <regex>
#include <optional>
#include <nlohmann/json.hpp>

namespace orpheus {
namespace utils {

/**
 * TypeResolver - Unified type parsing and value interpretation
 *
 * Consolidates the duplicated type checking logic across MCP handlers.
 * Handles Source 2 engine types (CHandle, Vector, QAngle, CUtlString, etc.)
 */
class TypeResolver {
public:
    enum class Category {
        Unknown,
        Bool,
        Int8,
        UInt8,
        Int16,
        UInt16,
        Int32,
        UInt32,
        Int64,
        UInt64,
        Float32,
        Float64,
        Pointer,
        Handle,      // CHandle<T> - 4 bytes, contains entity index
        Vector,      // Vector/Vector3 - 12 bytes (3 floats)
        QAngle,      // QAngle - 12 bytes (pitch, yaw, roll)
        Color,       // Color - 4 bytes (RGBA)
        String,      // CUtlString - pointer to string
        CharArray,   // char[N] - inline string
        Bitfield,    // bitfield:N
        Struct       // Unknown struct type
    };

    struct TypeInfo {
        Category category = Category::Unknown;
        size_t size = 0;           // Size in bytes (0 = unknown/variable)
        size_t array_size = 0;     // For char[N], array size
        bool is_pointer = false;
        bool is_array = false;
        std::string base_type;     // For templates like CHandle<T>, the inner type
    };

    /**
     * Parse a type string and return type information
     */
    static TypeInfo Parse(const std::string& type_str) {
        TypeInfo info;
        std::string type_lower = ToLower(type_str);

        // Check for pointer types
        if (type_str.find('*') != std::string::npos) {
            info.is_pointer = true;
            info.category = Category::Pointer;
            info.size = 8;
            return info;
        }

        // Check for char[N] array
        std::regex char_array_regex(R"(char\[(\d+)\])", std::regex::icase);
        std::smatch match;
        if (std::regex_search(type_str, match, char_array_regex)) {
            info.category = Category::CharArray;
            info.array_size = std::stoul(match[1].str());
            info.size = info.array_size;
            info.is_array = true;
            return info;
        }

        // Check for CHandle<T>
        std::regex handle_regex(R"(CHandle\s*<\s*([^>]+)\s*>)", std::regex::icase);
        if (std::regex_search(type_str, match, handle_regex)) {
            info.category = Category::Handle;
            info.size = 4;
            info.base_type = match[1].str();
            return info;
        }

        // Check for bitfield
        if (type_lower.find("bitfield") != std::string::npos) {
            info.category = Category::Bitfield;
            info.size = 0;  // Variable
            return info;
        }

        // Check for Vector types
        if (type_lower.find("vector") != std::string::npos &&
            type_lower.find("cutlvector") == std::string::npos) {
            info.category = Category::Vector;
            info.size = 12;
            return info;
        }

        // Check for QAngle
        if (type_lower.find("qangle") != std::string::npos) {
            info.category = Category::QAngle;
            info.size = 12;
            return info;
        }

        // Check for Color
        if (type_lower == "color") {
            info.category = Category::Color;
            info.size = 4;
            return info;
        }

        // Check for CUtlString
        if (type_lower.find("cutlstring") != std::string::npos ||
            type_lower.find("cutlsymbollarge") != std::string::npos) {
            info.category = Category::String;
            info.size = 8;  // Pointer
            return info;
        }

        // Primitive types
        if (type_lower.find("bool") != std::string::npos) {
            info.category = Category::Bool;
            info.size = 1;
        } else if (type_lower.find("int8") != std::string::npos) {
            info.category = Category::Int8;
            info.size = 1;
        } else if (type_lower.find("uint8") != std::string::npos ||
                   (type_lower == "char")) {
            info.category = Category::UInt8;
            info.size = 1;
        } else if (type_lower.find("int16") != std::string::npos ||
                   type_lower.find("short") != std::string::npos) {
            info.category = Category::Int16;
            info.size = 2;
        } else if (type_lower.find("uint16") != std::string::npos) {
            info.category = Category::UInt16;
            info.size = 2;
        } else if (type_lower.find("int32") != std::string::npos ||
                   type_lower == "int") {
            info.category = Category::Int32;
            info.size = 4;
        } else if (type_lower.find("uint32") != std::string::npos) {
            info.category = Category::UInt32;
            info.size = 4;
        } else if (type_lower.find("int64") != std::string::npos) {
            info.category = Category::Int64;
            info.size = 8;
        } else if (type_lower.find("uint64") != std::string::npos) {
            info.category = Category::UInt64;
            info.size = 8;
        } else if (type_lower.find("float64") != std::string::npos ||
                   type_lower.find("double") != std::string::npos) {
            info.category = Category::Float64;
            info.size = 8;
        } else if (type_lower.find("float") != std::string::npos) {
            info.category = Category::Float32;
            info.size = 4;
        } else {
            // Unknown struct - default to pointer size
            info.category = Category::Struct;
            info.size = 8;
        }

        return info;
    }

    /**
     * Get the read size for a type (minimum bytes needed)
     */
    static size_t GetReadSize(const std::string& type_str) {
        auto info = Parse(type_str);
        return info.size > 0 ? info.size : 8;  // Default to 8
    }

    /**
     * Interpret raw bytes as JSON value based on type
     */
    static nlohmann::json Interpret(const std::string& type_str,
                                    const std::vector<uint8_t>& data) {
        auto info = Parse(type_str);
        nlohmann::json result;

        if (data.empty()) {
            return nullptr;
        }

        switch (info.category) {
            case Category::Bool:
                if (data.size() >= 1) result = (data[0] != 0);
                break;

            case Category::Int8:
                if (data.size() >= 1) result = static_cast<int8_t>(data[0]);
                break;

            case Category::UInt8:
                if (data.size() >= 1) result = data[0];
                break;

            case Category::Int16:
                if (data.size() >= 2) {
                    int16_t v; std::memcpy(&v, data.data(), 2);
                    result = v;
                }
                break;

            case Category::UInt16:
                if (data.size() >= 2) {
                    uint16_t v; std::memcpy(&v, data.data(), 2);
                    result = v;
                }
                break;

            case Category::Int32:
                if (data.size() >= 4) {
                    int32_t v; std::memcpy(&v, data.data(), 4);
                    result = v;
                }
                break;

            case Category::UInt32:
                if (data.size() >= 4) {
                    uint32_t v; std::memcpy(&v, data.data(), 4);
                    result = v;
                }
                break;

            case Category::Int64:
                if (data.size() >= 8) {
                    int64_t v; std::memcpy(&v, data.data(), 8);
                    result = v;
                }
                break;

            case Category::UInt64:
                if (data.size() >= 8) {
                    uint64_t v; std::memcpy(&v, data.data(), 8);
                    result = v;
                }
                break;

            case Category::Float32:
                if (data.size() >= 4) {
                    float v; std::memcpy(&v, data.data(), 4);
                    result = v;
                }
                break;

            case Category::Float64:
                if (data.size() >= 8) {
                    double v; std::memcpy(&v, data.data(), 8);
                    result = v;
                }
                break;

            case Category::Pointer:
            case Category::String:
                if (data.size() >= 8) {
                    uint64_t v; std::memcpy(&v, data.data(), 8);
                    result = FormatAddress(v);
                }
                break;

            case Category::Handle:
                if (data.size() >= 4) {
                    uint32_t v; std::memcpy(&v, data.data(), 4);
                    result = nlohmann::json::object();
                    result["handle"] = v;
                    result["entity_index"] = v & 0x7FFF;
                }
                break;

            case Category::Vector:
                if (data.size() >= 12) {
                    float x, y, z;
                    std::memcpy(&x, data.data(), 4);
                    std::memcpy(&y, data.data() + 4, 4);
                    std::memcpy(&z, data.data() + 8, 4);
                    result = {{"x", x}, {"y", y}, {"z", z}};
                }
                break;

            case Category::QAngle:
                if (data.size() >= 12) {
                    float pitch, yaw, roll;
                    std::memcpy(&pitch, data.data(), 4);
                    std::memcpy(&yaw, data.data() + 4, 4);
                    std::memcpy(&roll, data.data() + 8, 4);
                    result = {{"pitch", pitch}, {"yaw", yaw}, {"roll", roll}};
                }
                break;

            case Category::Color:
                if (data.size() >= 4) {
                    result = {
                        {"r", data[0]}, {"g", data[1]},
                        {"b", data[2]}, {"a", data[3]}
                    };
                }
                break;

            case Category::CharArray:
                {
                    // Safely find null terminator within bounds
                    size_t max_len = std::min(data.size(), info.array_size);
                    size_t str_len = 0;
                    for (size_t i = 0; i < max_len; i++) {
                        if (data[i] == '\0') break;
                        str_len++;
                    }
                    result = std::string(reinterpret_cast<const char*>(data.data()), str_len);
                }
                break;

            default:
                // Return hex for unknown types
                result = ToHexString(data);
                break;
        }

        return result;
    }

    /**
     * Get entity index from a handle value
     */
    static uint32_t GetEntityIndex(uint32_t handle) {
        return handle & 0x7FFF;
    }

    /**
     * Check if type is a numeric primitive
     */
    static bool IsNumeric(Category cat) {
        return cat >= Category::Int8 && cat <= Category::Float64;
    }

private:
    static std::string ToLower(const std::string& str) {
        std::string result = str;
        for (auto& c : result) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return result;
    }

    static std::string FormatAddress(uint64_t addr) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << addr;
        return ss.str();
    }

    static std::string ToHexString(const std::vector<uint8_t>& data) {
        std::stringstream ss;
        for (uint8_t b : data) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return ss.str();
    }
};

} // namespace utils
} // namespace orpheus
