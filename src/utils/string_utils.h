#pragma once

#include <string>
#include <algorithm>
#include <cctype>

namespace orpheus::utils {

/**
 * String utility functions for case-insensitive operations and common transformations.
 */
namespace string_utils {

/**
 * Convert string to lowercase.
 */
inline std::string ToLower(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

/**
 * Convert string to uppercase.
 */
inline std::string ToUpper(const std::string& input) {
    std::string result = input;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return result;
}

/**
 * Case-insensitive string comparison.
 */
inline bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return ToLower(a) == ToLower(b);
}

/**
 * Case-insensitive substring search.
 */
inline bool ContainsIgnoreCase(const std::string& haystack, const std::string& needle) {
    return ToLower(haystack).find(ToLower(needle)) != std::string::npos;
}

/**
 * Sanitize string for use as filename (replace invalid chars with underscore).
 */
inline std::string SanitizeFilename(const std::string& name) {
    std::string safe = name;
    for (char& c : safe) {
        if (c == '!' || c == ':' || c == '\\' || c == '/' ||
            c == '*' || c == '?' || c == '"' || c == '<' ||
            c == '>' || c == '|') {
            c = '_';
        }
    }
    return safe;
}

/**
 * Trim whitespace from both ends of string.
 */
inline std::string Trim(const std::string& input) {
    size_t start = input.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = input.find_last_not_of(" \t\n\r");
    return input.substr(start, end - start + 1);
}

/**
 * Check if string starts with prefix (case-sensitive).
 */
inline bool StartsWith(const std::string& str, const std::string& prefix) {
    if (prefix.size() > str.size()) return false;
    return str.compare(0, prefix.size(), prefix) == 0;
}

/**
 * Check if string ends with suffix (case-sensitive).
 */
inline bool EndsWith(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

} // namespace string_utils
} // namespace orpheus::utils
