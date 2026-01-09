/**
 * MCP Handlers - CS2 Entity
 *
 * Counter-Strike 2 entity system handlers:
 * - HandleCS2Init (one-shot initialization)
 * - HandleCS2Identify
 * - HandleCS2ReadField
 * - HandleCS2Inspect
 * - HandleCS2GetLocalPlayer
 * - HandleCS2GetEntity
 * - Helper functions (StripTypePrefix, IdentifyClassFromPointer)
 */

#include "mcp_server.h"
#include "ui/application.h"
#include "core/dma_interface.h"
#include "dumper/cs2_schema.h"
#include "analysis/rtti_parser.h"
#include "utils/cache_manager.h"
#include "utils/string_utils.h"
#include "utils/type_resolver.h"
#include "utils/memory_reader.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <cstring>

using json = nlohmann::json;

namespace orpheus::mcp {

// Helper function to strip "class " or "struct " prefix from RTTI names
std::string MCPServer::StripTypePrefix(const std::string& name) {
    if (name.substr(0, 6) == "class ") return name.substr(6);
    if (name.substr(0, 7) == "struct ") return name.substr(7);
    return name;
}

// Helper function to identify class from an object pointer using RTTI
std::string MCPServer::IdentifyClassFromPointer(uint32_t pid, uint64_t ptr, uint64_t module_base) {
    auto* dma = app_->GetDMA();
    if (!dma || !dma->IsConnected()) return "";

    // Read vtable pointer at object+0
    auto vtable_data = dma->ReadMemory(pid, ptr, 8);
    if (vtable_data.size() < 8) return "";

    uint64_t vtable_addr;
    std::memcpy(&vtable_addr, vtable_data.data(), 8);
    if (vtable_addr == 0 || vtable_addr < 0x10000) return "";

    // Find module base if not provided
    if (module_base == 0) {
        auto modules = dma->GetModuleList(pid);
        for (const auto& mod : modules) {
            if (vtable_addr >= mod.base_address && vtable_addr < mod.base_address + mod.size) {
                module_base = mod.base_address;
                break;
            }
        }
        if (module_base == 0) return "";
    }

    // Use RTTI parser
    analysis::RTTIParser parser(
        [dma, pid](uint64_t addr, size_t size) {
            return dma->ReadMemory(pid, addr, size);
        },
        module_base
    );

    auto info = parser.ParseVTable(vtable_addr);
    if (!info) return "";

    // Return class name with prefix stripped
    return StripTypePrefix(info->demangled_name);
}

std::string MCPServer::HandleCS2Init(const std::string& body) {
    try {
        json req = json::parse(body);
        uint32_t pid = req.value("pid", 0);
        bool force_refresh = req.value("force_refresh", false);

        if (pid == 0) {
            return CreateErrorResponse("Missing required parameter: pid");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        json result;
        result["pid"] = pid;

        // ===== STEP 1: Initialize Schema System =====
        auto schemasystem_mod = dma->GetModuleByName(pid, "schemasystem.dll");
        if (!schemasystem_mod) {
            return CreateErrorResponse("schemasystem.dll not found - is this Counter-Strike 2?");
        }

        // Create or recreate dumper if PID changed
        if (cs2_schema_ && cs2_schema_pid_ != pid) {
            delete static_cast<orpheus::dumper::CS2SchemaDumper*>(cs2_schema_);
            cs2_schema_ = nullptr;
        }

        if (!cs2_schema_) {
            cs2_schema_ = new orpheus::dumper::CS2SchemaDumper(dma, pid);
            cs2_schema_pid_ = pid;
        }

        auto* dumper = static_cast<orpheus::dumper::CS2SchemaDumper*>(cs2_schema_);

        if (!dumper->Initialize(schemasystem_mod->base_address)) {
            return CreateErrorResponse("Failed to initialize CS2 Schema: " + dumper->GetLastError());
        }

        // ===== STEP 2: Dump Schema (or load from cache) =====
        uint32_t module_size = schemasystem_mod->size;
        std::string cache_key = "all_deduplicated";
        size_t class_count = 0;
        size_t field_count = 0;
        bool schema_cached = false;

        if (!force_refresh && cs2_schema_cache_.Exists(cache_key, module_size)) {
            std::string cached = cs2_schema_cache_.Load(cache_key, module_size);
            if (!cached.empty()) {
                json cache_data = json::parse(cached);
                class_count = cache_data.contains("classes") ? cache_data["classes"].size() : 0;
                // Count fields
                if (cache_data.contains("classes")) {
                    for (const auto& cls : cache_data["classes"]) {
                        if (cls.contains("fields")) {
                            field_count += cls["fields"].size();
                        }
                    }
                }
                schema_cached = true;
            }
        }

        if (!schema_cached) {
            // Perform fresh dump with deduplication (built into DumpAllDeduplicated)
            auto all_classes = dumper->DumpAllDeduplicated();
            class_count = all_classes.size();

            // Build cache data
            json cache_data;
            cache_data["scope"] = cache_key;
            cache_data["scopes_processed"] = dumper->GetScopes().size();
            cache_data["deduplicated"] = true;
            cache_data["classes"] = json::array();

            for (const auto& cls : all_classes) {
                json c;
                c["name"] = cls.name;
                c["module"] = cls.module;
                c["size"] = cls.size;
                c["base_class"] = cls.base_class;

                json fields = json::array();
                for (const auto& field : cls.fields) {
                    json f;
                    f["name"] = field.name;
                    f["offset"] = field.offset;
                    f["type"] = field.type_name;
                    f["size"] = field.size;
                    fields.push_back(f);
                    field_count++;
                }
                c["fields"] = fields;
                cache_data["classes"].push_back(c);
            }

            cs2_schema_cache_.Save(cache_key, module_size, cache_data.dump(2));
        }

        json schema_info;
        schema_info["scopes"] = dumper->GetScopes().size();
        schema_info["classes"] = class_count;
        schema_info["fields"] = field_count;
        schema_info["cached"] = schema_cached;
        result["schema"] = schema_info;

        // ===== STEP 3: Initialize Entity System =====
        auto client_mod = dma->GetModuleByName(pid, "client.dll");
        if (!client_mod) {
            result["entity_system"] = nullptr;
            result["warning"] = "client.dll not found - entity system not initialized";
            return CreateSuccessResponse(result.dump());
        }

        cs2_entity_cache_.client_base = client_mod->base_address;
        cs2_entity_cache_.client_size = client_mod->size;

        // ===== STEP 3.5: RTTI Scan for client.dll (enables class identification) =====
        json rtti_info;
        size_t rtti_class_count = 0;
        bool rtti_cached = false;

        if (!force_refresh && rtti_cache_.Exists("client.dll", client_mod->size)) {
            std::string cached_rtti = rtti_cache_.Load("client.dll", client_mod->size);
            if (!cached_rtti.empty()) {
                json rtti_data = json::parse(cached_rtti);
                rtti_class_count = rtti_data.contains("classes") ? rtti_data["classes"].size() : 0;
                rtti_cached = true;
            }
        }

        if (!rtti_cached) {
            // Perform RTTI scan
            analysis::RTTIParser parser(
                [dma, pid](uint64_t addr, size_t size) {
                    return dma->ReadMemory(pid, addr, size);
                },
                client_mod->base_address
            );

            // Collect discovered classes via callback
            std::vector<analysis::RTTIClassInfo> found_classes;
            rtti_class_count = parser.ScanModule(client_mod->base_address,
                [&found_classes](const analysis::RTTIClassInfo& info) {
                    found_classes.push_back(info);
                });

            if (!found_classes.empty()) {
                // Build cache
                json cache_data;
                cache_data["module"] = "client.dll";
                cache_data["module_base_rva"] = 0;  // RVA from module base
                cache_data["scan_size"] = client_mod->size;

                json classes_array = json::array();
                for (const auto& info : found_classes) {
                    json cls;
                    cls["vtable_rva"] = info.vtable_address - client_mod->base_address;
                    cls["methods"] = info.method_count;
                    cls["flags"] = info.GetFlags();
                    cls["type"] = info.demangled_name;
                    cls["hierarchy"] = info.GetHierarchyString();
                    classes_array.push_back(cls);
                }
                cache_data["classes"] = classes_array;

                rtti_cache_.Save("client.dll", client_mod->size, cache_data.dump(2));
            }
        }

        rtti_info["module"] = "client.dll";
        rtti_info["classes"] = rtti_class_count;
        rtti_info["cached"] = rtti_cached;
        result["rtti"] = rtti_info;

        // Pattern: CGameEntitySystem
        const uint8_t entity_system_pattern[] = {
            0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xD3,
            0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xF0
        };
        const char entity_system_mask[] = "xxx????xx????xxx";

        // Pattern: LocalPlayerController array
        const uint8_t local_player_pattern[] = {
            0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04, 0xC1
        };
        const char local_player_mask[] = "xxx????xxxx";

        auto client_data = dma->ReadMemory(pid, client_mod->base_address, client_mod->size);
        if (client_data.empty()) {
            result["entity_system"] = nullptr;
            result["warning"] = "Failed to read client.dll memory";
            return CreateSuccessResponse(result.dump());
        }

        uint64_t entity_system_match = 0;
        uint64_t local_player_match = 0;

        // Search for entity system pattern
        for (size_t i = 0; i + sizeof(entity_system_pattern) < client_data.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < sizeof(entity_system_pattern); j++) {
                if (entity_system_mask[j] == 'x' && client_data[i + j] != entity_system_pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                entity_system_match = client_mod->base_address + i;
                break;
            }
        }

        // Search for local player pattern
        for (size_t i = 0; i + sizeof(local_player_pattern) < client_data.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < sizeof(local_player_pattern); j++) {
                if (local_player_mask[j] == 'x' && client_data[i + j] != local_player_pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                local_player_match = client_mod->base_address + i;
                break;
            }
        }

        // Resolve entity system pointer
        if (entity_system_match != 0) {
            int32_t offset;
            std::memcpy(&offset, client_data.data() + (entity_system_match - client_mod->base_address) + 3, 4);
            uint64_t ptr_addr = entity_system_match + 7 + offset;

            auto ptr_data = dma->ReadMemory(pid, ptr_addr, 8);
            if (ptr_data.size() == 8) {
                std::memcpy(&cs2_entity_cache_.entity_system, ptr_data.data(), 8);
            }
        }

        // Resolve local player controller array
        if (local_player_match != 0) {
            int32_t offset;
            std::memcpy(&offset, client_data.data() + (local_player_match - client_mod->base_address) + 3, 4);
            cs2_entity_cache_.local_player_controller = local_player_match + 7 + offset;
        }

        if (cs2_entity_cache_.entity_system != 0 && cs2_entity_cache_.local_player_controller != 0) {
            cs2_entity_cache_.initialized = true;
        }

        result["entity_system"] = FormatAddress(cs2_entity_cache_.entity_system);
        result["client_base"] = FormatAddress(cs2_entity_cache_.client_base);
        result["client_size"] = cs2_entity_cache_.client_size;

        // ===== STEP 4: Get Local Player Info =====
        json local_player;
        if (cs2_entity_cache_.initialized) {
            uint64_t controller_ptr_addr = cs2_entity_cache_.local_player_controller;
            auto ptr_data = dma->ReadMemory(pid, controller_ptr_addr, 8);
            if (ptr_data.size() >= 8) {
                uint64_t controller;
                std::memcpy(&controller, ptr_data.data(), 8);

                if (controller != 0) {
                    local_player["controller"] = FormatAddress(controller);

                    // Identify class
                    std::string class_name = IdentifyClassFromPointer(pid, controller, cs2_entity_cache_.client_base);
                    if (!class_name.empty()) {
                        local_player["controller_class"] = class_name;
                    }

                    // Read key fields from schema
                    uint32_t pawn_offset = dumper->GetOffset("CCSPlayerController", "m_hPlayerPawn");
                    if (pawn_offset != 0) {
                        auto pawn_data = dma->ReadMemory(pid, controller + pawn_offset, 4);
                        if (pawn_data.size() >= 4) {
                            uint32_t pawn_handle;
                            std::memcpy(&pawn_handle, pawn_data.data(), 4);
                            local_player["pawn_handle"] = pawn_handle;
                            local_player["pawn_entity_index"] = pawn_handle & 0x7FFF;
                        }
                    }

                    uint32_t health_offset = dumper->GetOffset("CCSPlayerController", "m_iPawnHealth");
                    if (health_offset != 0) {
                        auto health_data = dma->ReadMemory(pid, controller + health_offset, 4);
                        if (health_data.size() >= 4) {
                            uint32_t health;
                            std::memcpy(&health, health_data.data(), 4);
                            local_player["health"] = health;
                        }
                    }

                    uint32_t armor_offset = dumper->GetOffset("CCSPlayerController", "m_iPawnArmor");
                    if (armor_offset != 0) {
                        auto armor_data = dma->ReadMemory(pid, controller + armor_offset, 4);
                        if (armor_data.size() >= 4) {
                            int32_t armor;
                            std::memcpy(&armor, armor_data.data(), 4);
                            local_player["armor"] = armor;
                        }
                    }
                }
            }
        }
        result["local_player"] = local_player.empty() ? json(nullptr) : local_player;
        result["ready"] = cs2_entity_cache_.initialized && !local_player.empty();

        LOG_INFO("CS2 initialized: {} classes, {} fields, entity_system={}, ready={}",
                 class_count, field_count,
                 FormatAddress(cs2_entity_cache_.entity_system),
                 result["ready"].get<bool>());

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleCS2Identify(const std::string& body) {
    try {
        json req = json::parse(body);
        uint32_t pid = req.value("pid", 0);
        std::string address_str = req.value("address", "");

        if (pid == 0) {
            return CreateErrorResponse("Missing required parameter: pid");
        }
        if (address_str.empty()) {
            return CreateErrorResponse("Missing required parameter: address");
        }

        uint64_t address = std::stoull(address_str, nullptr, 16);
        if (address == 0) {
            return CreateErrorResponse("Invalid address: NULL pointer");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Identify class via RTTI
        std::string class_name = IdentifyClassFromPointer(pid, address, cs2_entity_cache_.client_base);
        if (class_name.empty()) {
            return CreateErrorResponse("Could not identify class - no valid RTTI found at address");
        }

        json result;
        result["address"] = FormatAddress(address);
        result["class_name"] = class_name;

        // Try to find matching schema class
        if (cs2_schema_) {
            auto* dumper = static_cast<orpheus::dumper::CS2SchemaDumper*>(cs2_schema_);
            if (dumper->IsInitialized()) {
                const orpheus::dumper::SchemaClass* schema_class = dumper->FindClass(class_name);
                if (schema_class) {
                    result["schema_found"] = true;
                    result["schema_class"] = schema_class->name;
                    result["schema_size"] = schema_class->size;
                    result["field_count"] = schema_class->fields.size();
                    result["base_class"] = schema_class->base_class;
                } else {
                    result["schema_found"] = false;
                }
            }
        }

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleCS2ReadField(const std::string& body) {
    try {
        json req = json::parse(body);
        uint32_t pid = req.value("pid", 0);
        std::string address_str = req.value("address", "");
        std::string field_name = req.value("field", "");
        std::string class_name = req.value("class", "");  // Optional - auto-detect if not provided

        if (pid == 0) {
            return CreateErrorResponse("Missing required parameter: pid");
        }
        if (address_str.empty()) {
            return CreateErrorResponse("Missing required parameter: address");
        }
        if (field_name.empty()) {
            return CreateErrorResponse("Missing required parameter: field");
        }

        uint64_t address = std::stoull(address_str, nullptr, 16);
        if (address == 0) {
            return CreateErrorResponse("Invalid address: NULL pointer");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Auto-detect class if not provided
        if (class_name.empty()) {
            class_name = IdentifyClassFromPointer(pid, address, cs2_entity_cache_.client_base);
            if (class_name.empty()) {
                return CreateErrorResponse("Could not auto-detect class - please provide 'class' parameter");
            }
        }

        // Look up field from cache (ASLR-safe - offsets are class-relative)
        namespace fs = std::filesystem;
        std::string cache_dir = cs2_schema_cache_.GetDirectory();

        std::string class_lower = utils::string_utils::ToLower(class_name);
        std::string field_lower = utils::string_utils::ToLower(field_name);

        uint32_t field_offset = 0;
        uint32_t field_size = 0;
        std::string field_type;
        bool found = false;

        for (const auto& entry : fs::directory_iterator(cache_dir)) {
            if (entry.path().extension() != ".json") continue;

            std::ifstream in(entry.path());
            if (!in.is_open()) continue;

            try {
                json cache_data = json::parse(in);
                if (!cache_data.contains("classes")) continue;

                for (const auto& cls : cache_data["classes"]) {
                    std::string cls_name = cls.value("name", "");
                    if (utils::string_utils::ToLower(cls_name) != class_lower) continue;

                    if (cls.contains("fields")) {
                        for (const auto& fld : cls["fields"]) {
                            std::string fld_name = fld.value("name", "");
                            if (utils::string_utils::ToLower(fld_name) == field_lower) {
                                field_offset = fld.value("offset", 0);
                                field_size = fld.value("size", 0);
                                field_type = fld.value("type", "");
                                field_name = fld_name;  // Use actual case from cache
                                class_name = cls_name;
                                found = true;
                                break;
                            }
                        }
                    }
                    if (found) break;
                }
            } catch (...) { continue; }
            if (found) break;
        }

        if (!found) {
            return CreateErrorResponse("Field not found in cache: " + field_name + " in class " + class_name);
        }

        // Read field value using TypeResolver
        uint64_t field_addr = address + field_offset;
        size_t read_size = field_size > 0 ? field_size : utils::TypeResolver::GetReadSize(field_type);

        auto data = dma->ReadMemory(pid, field_addr, read_size);
        if (data.empty()) {
            return CreateErrorResponse("Failed to read memory at field address");
        }

        json result;
        result["address"] = FormatAddress(address);
        result["class"] = class_name;
        result["field"] = field_name;
        result["type"] = field_type;
        result["offset"] = field_offset;
        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << field_offset;
        result["offset_hex"] = ss.str();
        result["field_address"] = FormatAddress(field_addr);

        // Interpret value using TypeResolver
        auto type_info = utils::TypeResolver::Parse(field_type);
        json interpreted = utils::TypeResolver::Interpret(field_type, data);

        if (!interpreted.is_null()) {
            // Handle special cases for entity_index from handles
            if (type_info.category == utils::TypeResolver::Category::Handle && interpreted.is_object()) {
                result["value"] = interpreted["handle"];
                result["entity_index"] = interpreted["entity_index"];
            } else {
                result["value"] = interpreted;
            }
        } else {
            // Return raw hex for failed interpretation
            std::stringstream hex_ss;
            for (size_t i = 0; i < data.size(); i++) {
                hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
            }
            result["value_hex"] = hex_ss.str();
        }

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleCS2Inspect(const std::string& body) {
    try {
        json req = json::parse(body);
        uint32_t pid = req.value("pid", 0);
        std::string address_str = req.value("address", "");
        std::string class_name = req.value("class", "");
        int max_fields = req.value("max_fields", 50);

        if (pid == 0) {
            return CreateErrorResponse("Missing required parameter: pid");
        }
        if (address_str.empty()) {
            return CreateErrorResponse("Missing required parameter: address");
        }

        uint64_t address = std::stoull(address_str, nullptr, 16);
        if (address == 0) {
            return CreateErrorResponse("Invalid address: NULL pointer");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Auto-detect class if not provided
        if (class_name.empty()) {
            class_name = IdentifyClassFromPointer(pid, address, cs2_entity_cache_.client_base);
            if (class_name.empty()) {
                return CreateErrorResponse("Could not auto-detect class - please provide 'class' parameter");
            }
        }

        // Look up class from cache (ASLR-safe - offsets are class-relative)
        namespace fs = std::filesystem;
        std::string cache_dir = cs2_schema_cache_.GetDirectory();
        std::string class_lower = utils::string_utils::ToLower(class_name);

        json cached_class;
        bool found_class = false;

        for (const auto& entry : fs::directory_iterator(cache_dir)) {
            if (entry.path().extension() != ".json") continue;

            std::ifstream in(entry.path());
            if (!in.is_open()) continue;

            try {
                json cache_data = json::parse(in);
                if (!cache_data.contains("classes")) continue;

                for (const auto& cls : cache_data["classes"]) {
                    std::string cls_name = cls.value("name", "");
                    if (utils::string_utils::ToLower(cls_name) == class_lower) {
                        cached_class = cls;
                        class_name = cls_name;  // Use actual case
                        found_class = true;
                        break;
                    }
                }
            } catch (...) { continue; }
            if (found_class) break;
        }

        if (!found_class) {
            return CreateErrorResponse("Schema class not found in cache: " + class_name);
        }

        json result;
        result["address"] = FormatAddress(address);
        result["class"] = class_name;
        result["base_class"] = cached_class.value("base_class", "");
        result["size"] = cached_class.value("size", 0);

        json fields_out = json::array();
        int field_count = 0;

        if (cached_class.contains("fields")) {
            for (const auto& field : cached_class["fields"]) {
                if (field_count >= max_fields) break;

                std::string fld_name = field.value("name", "");
                std::string fld_type = field.value("type", "");
                uint32_t fld_offset = field.value("offset", 0);

                json f;
                f["name"] = fld_name;
                f["type"] = fld_type;
                f["offset"] = fld_offset;
                std::stringstream ss;
                ss << "0x" << std::hex << std::uppercase << fld_offset;
                f["offset_hex"] = ss.str();

                // Read field value using TypeResolver
                uint64_t field_addr = address + fld_offset;
                size_t read_size = utils::TypeResolver::GetReadSize(fld_type);

                auto data = dma->ReadMemory(pid, field_addr, read_size);
                if (!data.empty()) {
                    json interpreted = utils::TypeResolver::Interpret(fld_type, data);
                    if (!interpreted.is_null()) {
                        f["value"] = interpreted;
                    }
                }

                fields_out.push_back(f);
                field_count++;
            }
        }

        result["fields"] = fields_out;
        result["field_count"] = cached_class.contains("fields") ? cached_class["fields"].size() : 0;
        result["fields_shown"] = field_count;

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleCS2GetLocalPlayer(const std::string& body) {
    try {
        json req = json::parse(body);
        uint32_t pid = req.value("pid", 0);
        int slot = req.value("slot", 0);

        if (pid == 0) {
            return CreateErrorResponse("Missing required parameter: pid");
        }

        if (!cs2_entity_cache_.initialized) {
            return CreateErrorResponse("CS2 Entity system not initialized - call cs2_init first");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Create typed memory reader
        auto reader = utils::MakeReader(dma, pid);

        // Read local player controller from array
        uint64_t controller_ptr_addr = cs2_entity_cache_.local_player_controller + slot * 8;
        auto controller = reader.ReadPtr(controller_ptr_addr);
        if (!controller) {
            return CreateErrorResponse("Failed to read local player controller pointer");
        }

        if (*controller == 0) {
            json result;
            result["slot"] = slot;
            result["controller"] = nullptr;
            result["message"] = "No local player at this slot";
            return CreateSuccessResponse(result.dump());
        }

        json result;
        result["slot"] = slot;
        result["controller"] = FormatAddress(*controller);

        // Try to identify the controller class
        std::string class_name = IdentifyClassFromPointer(pid, *controller, cs2_entity_cache_.client_base);
        if (!class_name.empty()) {
            result["controller_class"] = class_name;
        }

        // Try to read pawn handle from controller
        if (cs2_schema_) {
            auto* dumper = static_cast<orpheus::dumper::CS2SchemaDumper*>(cs2_schema_);

            uint32_t pawn_offset = dumper->GetOffset("CCSPlayerController", "m_hPlayerPawn");
            if (pawn_offset != 0) {
                if (auto pawn_handle = reader.ReadU32(*controller + pawn_offset)) {
                    result["pawn_handle"] = *pawn_handle;
                    result["pawn_entity_index"] = *pawn_handle & 0x7FFF;
                }
            }

            uint32_t health_offset = dumper->GetOffset("CCSPlayerController", "m_iPawnHealth");
            if (health_offset != 0) {
                if (auto health = reader.ReadU32(*controller + health_offset)) {
                    result["health"] = *health;
                }
            }

            uint32_t armor_offset = dumper->GetOffset("CCSPlayerController", "m_iPawnArmor");
            if (armor_offset != 0) {
                if (auto armor = reader.ReadI32(*controller + armor_offset)) {
                    result["armor"] = *armor;
                }
            }
        }

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleCS2GetEntity(const std::string& body) {
    try {
        json req = json::parse(body);
        uint32_t pid = req.value("pid", 0);
        uint32_t handle = req.value("handle", 0);
        int index = req.value("index", -1);

        if (pid == 0) {
            return CreateErrorResponse("Missing required parameter: pid");
        }
        if (handle == 0 && index < 0) {
            return CreateErrorResponse("Missing required parameter: handle or index");
        }

        if (!cs2_entity_cache_.initialized || cs2_entity_cache_.entity_system == 0) {
            return CreateErrorResponse("CS2 Entity system not initialized - call cs2_init first");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Create typed memory reader
        auto reader = utils::MakeReader(dma, pid);

        // Calculate entity index from handle if needed
        int entity_index = index >= 0 ? index : (handle & 0x7FFF);

        // Entity list is at EntitySystem + 0x10, organized in chunks of 512
        // Each chunk pointer is at EntitySystem + 0x10 + chunk_index * 8
        // Within chunk: 8-byte header, then entries at stride 0x70

        int chunk_index = entity_index / 512;
        int slot = entity_index % 512;

        // Read chunk pointer
        uint64_t chunk_ptr_addr = cs2_entity_cache_.entity_system + 0x10 + chunk_index * 8;
        auto chunk_base_opt = reader.ReadPtr(chunk_ptr_addr);
        if (!chunk_base_opt) {
            return CreateErrorResponse("Failed to read entity chunk pointer");
        }

        // Some entity systems have flags in low bits
        uint64_t chunk_base = *chunk_base_opt & ~0xFULL;

        if (chunk_base == 0) {
            json result;
            result["entity_index"] = entity_index;
            result["entity"] = nullptr;
            result["message"] = "Entity chunk not allocated";
            return CreateSuccessResponse(result.dump());
        }

        // Read entity pointer from chunk (entries start at +8, stride 0x70)
        uint64_t entity_entry_addr = chunk_base + 0x08 + slot * 0x70;
        auto entity = reader.ReadPtr(entity_entry_addr);
        if (!entity) {
            return CreateErrorResponse("Failed to read entity entry");
        }

        if (*entity == 0) {
            json result;
            result["entity_index"] = entity_index;
            result["entity"] = nullptr;
            result["message"] = "Entity slot is empty";
            return CreateSuccessResponse(result.dump());
        }

        json result;
        result["entity_index"] = entity_index;
        result["chunk"] = chunk_index;
        result["slot"] = slot;
        result["entity"] = FormatAddress(*entity);

        // Try to identify entity class via RTTI
        std::string class_name = IdentifyClassFromPointer(pid, *entity, cs2_entity_cache_.client_base);
        if (!class_name.empty()) {
            result["class"] = class_name;
        }

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

} // namespace orpheus::mcp
