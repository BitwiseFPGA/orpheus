// Type Injector for Ghidra Decompiler - CS2 Schema Integration
// Copyright (C) 2025 Orpheus Project
// GPL-3.0 License
//
// This module provides deep integration between CS2 schema data and the
// Ghidra decompiler's type system. Instead of post-processing output,
// we inject types directly into Ghidra's TypeFactory before decompilation.

#pragma once

#ifdef ORPHEUS_HAS_GHIDRA_DECOMPILER

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

// Use the existing dumper schema structures directly
#include "dumper/cs2_schema.h"

// Forward declarations - Ghidra types
namespace ghidra {
    class Architecture;
    class TypeFactory;
    class Datatype;
    class TypeStruct;
    class TypePointer;
}

namespace orpheus {

/// \brief Injects CS2 schema types into Ghidra's TypeFactory
///
/// This class converts CS2 schema definitions into Ghidra's internal
/// type representation, enabling the decompiler to understand struct
/// layouts and produce output with proper field names.
class TypeInjector {
public:
    TypeInjector() = default;
    ~TypeInjector() = default;

    /// Set the target architecture (must be called before injection)
    /// @param arch Pointer to initialized Ghidra architecture
    void SetArchitecture(ghidra::Architecture* arch);

    /// Add a schema class definition to be injected
    /// @param class_def The schema class definition
    void AddSchemaClass(const orpheus::dumper::SchemaClass& class_def);

    /// Add multiple schema class definitions
    /// @param classes Vector of schema class definitions
    void AddSchemaClasses(const std::vector<orpheus::dumper::SchemaClass>& classes);

    /// Clear all pending schema classes
    void ClearSchemaClasses();

    /// Inject all added schema classes into the type factory
    /// @return Number of types successfully injected
    int InjectTypes();

    /// Check if a type has been injected by name
    /// @param name The type name to check
    /// @return true if the type exists in the factory
    bool HasType(const std::string& name) const;

    /// Get the Ghidra datatype for a schema class
    /// @param class_name The schema class name
    /// @return Pointer to Ghidra datatype, or nullptr if not found
    ghidra::Datatype* GetType(const std::string& class_name) const;

    /// Get a pointer type to a schema class (for 'this' parameter)
    /// @param class_name The schema class name
    /// @return Pointer to Ghidra pointer-to-struct type, or nullptr if not found
    ghidra::Datatype* GetPointerType(const std::string& class_name);

    /// Get the number of injected types
    int GetInjectedCount() const { return injected_count_; }

    /// Get any error messages from the last injection
    const std::string& GetLastError() const { return last_error_; }

private:
    /// Convert a schema type name to a Ghidra datatype
    /// @param type_name The schema type name
    /// @param size Size hint for unknown types
    /// @return Ghidra datatype (never null - returns unknown type as fallback)
    ghidra::Datatype* ResolveType(const std::string& type_name, uint32_t size);

    /// Create a struct type from schema class definition
    /// @param class_def The schema class definition
    /// @return The created Ghidra TypeStruct
    ghidra::TypeStruct* CreateStructType(const orpheus::dumper::SchemaClass& class_def);

    /// Parse a type string to extract base type and modifiers
    /// @param type_str The type string (e.g., "int32*", "Vector[3]")
    /// @param base_type Output: base type name
    /// @param is_pointer Output: true if pointer
    /// @param is_array Output: true if array
    /// @param array_count Output: array element count
    void ParseTypeString(const std::string& type_str,
                        std::string& base_type,
                        bool& is_pointer,
                        bool& is_array,
                        uint32_t& array_count);

    ghidra::Architecture* architecture_ = nullptr;
    ghidra::TypeFactory* type_factory_ = nullptr;
    std::vector<orpheus::dumper::SchemaClass> pending_classes_;
    std::unordered_map<std::string, ghidra::Datatype*> injected_types_;
    int injected_count_ = 0;
    std::string last_error_;
};

} // namespace orpheus

#endif // ORPHEUS_HAS_GHIDRA_DECOMPILER
