/**
 * MCP Handlers - Function Recovery
 *
 * Function recovery and analysis handlers:
 * - HandleRecoverFunctions
 * - HandleGetFunctionAt
 * - HandleGetFunctionContaining
 */

#include "mcp_server.h"
#include "ui/application.h"
#include "core/dma_interface.h"
#include "analysis/function_recovery.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace orpheus::mcp {

std::string MCPServer::HandleRecoverFunctions(const std::string& body) {
    try {
        auto req = json::parse(body);
        uint32_t pid = req["pid"];
        uint64_t module_base = std::stoull(req["module_base"].get<std::string>(), nullptr, 16);
        bool force_rescan = req.value("force_rescan", false);

        // Optional parameters
        bool use_prologues = req.value("use_prologues", true);
        bool follow_calls = req.value("follow_calls", true);
        bool use_exception_data = req.value("use_exception_data", true);
        size_t max_functions = req.value("max_functions", 100000);

        // Validate
        if (module_base == 0) {
            return CreateErrorResponse("Invalid module_base: cannot recover functions from NULL (0x0)");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected - check hardware connection");
        }

        // Verify process
        auto proc_info = dma->GetProcessInfo(pid);
        if (!proc_info) {
            return CreateErrorResponse("Process not found: PID " + std::to_string(pid));
        }

        // Find module info
        auto modules = dma->GetModuleList(pid);
        std::string module_name;
        uint32_t module_size = 0;
        bool is_64bit = true;

        for (const auto& mod : modules) {
            if (mod.base_address == module_base) {
                module_name = mod.name;
                module_size = mod.size;
                is_64bit = mod.is_64bit;
                break;
            }
        }

        if (module_name.empty()) {
            return CreateErrorResponse("Module not found at specified base address");
        }

        // Check cache first
        if (!force_rescan && function_cache_.Exists(module_name, module_size)) {
            std::string cached = function_cache_.Load(module_name, module_size);
            if (!cached.empty()) {
                json cache_data = json::parse(cached);

                json result;
                result["status"] = "cached";
                result["module"] = module_name;
                result["module_base"] = FormatAddress(module_base);
                result["module_size"] = module_size;
                result["count"] = cache_data.value("count", 0);
                result["cache_file"] = function_cache_.GetFilePath(module_name, module_size);
                result["summary"] = cache_data.value("summary", json::object());
                result["hint"] = "Use get_function_at or get_function_containing to query functions";

                LOG_INFO("Function cache hit for {} ({} functions)", module_name,
                         cache_data.value("count", 0));

                return CreateSuccessResponse(result.dump());
            }
        }

        // Perform recovery
        LOG_INFO("Recovering functions from {} at 0x{:X}...", module_name, module_base);

        analysis::FunctionRecovery recovery(
            [dma, pid](uint64_t addr, size_t size) {
                return dma->ReadMemory(pid, addr, size);
            },
            module_base,
            module_size,
            is_64bit
        );

        analysis::FunctionRecoveryOptions opts;
        opts.use_prologues = use_prologues;
        opts.follow_calls = follow_calls;
        opts.use_exception_data = use_exception_data;
        opts.max_functions = max_functions;

        auto functions = recovery.RecoverFunctions(opts);

        // Build cache data
        json cache_data;
        cache_data["module"] = module_name;
        cache_data["module_base"] = FormatAddress(module_base);
        cache_data["module_size"] = module_size;
        cache_data["count"] = functions.size();

        // Summary stats
        int pdata_count = 0, prologue_count = 0, call_count = 0;
        int thunk_count = 0, leaf_count = 0;
        for (const auto& [addr, func] : functions) {
            switch (func.source) {
                case analysis::FunctionInfo::Source::ExceptionData: pdata_count++; break;
                case analysis::FunctionInfo::Source::Prologue: prologue_count++; break;
                case analysis::FunctionInfo::Source::CallTarget: call_count++; break;
                default: break;
            }
            if (func.is_thunk) thunk_count++;
            if (func.is_leaf) leaf_count++;
        }

        cache_data["summary"] = {
            {"from_pdata", pdata_count},
            {"from_prologue", prologue_count},
            {"from_call_target", call_count},
            {"thunks", thunk_count},
            {"leaf_functions", leaf_count}
        };

        // Store functions with RVAs
        json funcs_array = json::array();
        for (const auto& [addr, func] : functions) {
            json f;
            f["rva"] = addr - module_base;
            f["size"] = func.size;
            f["source"] = func.GetSourceString();
            f["confidence"] = func.confidence;
            if (!func.name.empty()) {
                f["name"] = func.name;
            }
            f["is_thunk"] = func.is_thunk;
            f["is_leaf"] = func.is_leaf;
            f["instruction_count"] = func.instruction_count;
            f["basic_block_count"] = func.basic_block_count;
            funcs_array.push_back(f);
        }
        cache_data["functions"] = funcs_array;

        // Save to cache
        function_cache_.Save(module_name, module_size, cache_data.dump(2));

        // Return summary
        json result;
        result["status"] = "recovered";
        result["module"] = module_name;
        result["module_base"] = FormatAddress(module_base);
        result["module_size"] = module_size;
        result["count"] = functions.size();
        result["summary"] = cache_data["summary"];
        result["cache_file"] = function_cache_.GetFilePath(module_name, module_size);
        result["hint"] = "Use get_function_at or get_function_containing to query functions";

        LOG_INFO("Recovered {} functions from {}", functions.size(), module_name);

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleGetFunctionAt(const std::string& body) {
    try {
        auto req = json::parse(body);
        uint32_t pid = req["pid"];
        uint64_t address = std::stoull(req["address"].get<std::string>(), nullptr, 16);

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Find containing module
        auto modules = dma->GetModuleList(pid);
        std::string module_name;
        uint64_t module_base = 0;
        uint32_t module_size = 0;

        for (const auto& mod : modules) {
            if (address >= mod.base_address && address < mod.base_address + mod.size) {
                module_name = mod.name;
                module_base = mod.base_address;
                module_size = mod.size;
                break;
            }
        }

        if (module_name.empty()) {
            return CreateErrorResponse("Address not within any loaded module");
        }

        // Load from cache
        if (!function_cache_.Exists(module_name, module_size)) {
            return CreateErrorResponse("Functions not recovered for " + module_name +
                                       " - run recover_functions first");
        }

        std::string cached = function_cache_.Load(module_name, module_size);
        if (cached.empty()) {
            return CreateErrorResponse("Failed to load function cache");
        }

        json cache_data = json::parse(cached);
        uint64_t target_rva = address - module_base;

        // Exact match search
        for (const auto& func : cache_data["functions"]) {
            uint64_t rva = func["rva"].get<uint64_t>();
            if (rva == target_rva) {
                json result;
                result["found"] = true;
                result["address"] = FormatAddress(address);
                result["rva"] = rva;
                result["module"] = module_name;
                result["size"] = func.value("size", 0);
                result["source"] = func.value("source", "");
                result["confidence"] = func.value("confidence", 0.0);
                result["name"] = func.value("name", "");
                result["is_thunk"] = func.value("is_thunk", false);
                result["is_leaf"] = func.value("is_leaf", false);
                result["instruction_count"] = func.value("instruction_count", 0);
                result["basic_block_count"] = func.value("basic_block_count", 0);

                return CreateSuccessResponse(result.dump());
            }
        }

        json result;
        result["found"] = false;
        result["address"] = FormatAddress(address);
        result["module"] = module_name;
        result["hint"] = "No function starts at this exact address";

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleGetFunctionContaining(const std::string& body) {
    try {
        auto req = json::parse(body);
        uint32_t pid = req["pid"];
        uint64_t address = std::stoull(req["address"].get<std::string>(), nullptr, 16);

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        // Find containing module
        auto modules = dma->GetModuleList(pid);
        std::string module_name;
        uint64_t module_base = 0;
        uint32_t module_size = 0;

        for (const auto& mod : modules) {
            if (address >= mod.base_address && address < mod.base_address + mod.size) {
                module_name = mod.name;
                module_base = mod.base_address;
                module_size = mod.size;
                break;
            }
        }

        if (module_name.empty()) {
            return CreateErrorResponse("Address not within any loaded module");
        }

        // Load from cache
        if (!function_cache_.Exists(module_name, module_size)) {
            return CreateErrorResponse("Functions not recovered for " + module_name +
                                       " - run recover_functions first");
        }

        std::string cached = function_cache_.Load(module_name, module_size);
        if (cached.empty()) {
            return CreateErrorResponse("Failed to load function cache");
        }

        json cache_data = json::parse(cached);
        uint64_t target_rva = address - module_base;

        // Find function containing address (largest RVA <= target)
        json best_match;
        uint64_t best_rva = 0;

        for (const auto& func : cache_data["functions"]) {
            uint64_t rva = func["rva"].get<uint64_t>();
            uint32_t size = func.value("size", 0);

            if (rva <= target_rva && rva > best_rva) {
                // Check if address is within function bounds
                if (size > 0 && target_rva >= rva + size) {
                    continue;  // Address is past function end
                }
                best_match = func;
                best_rva = rva;
            }
        }

        if (!best_match.empty()) {
            json result;
            result["found"] = true;
            result["address"] = FormatAddress(address);
            result["function_start"] = FormatAddress(module_base + best_rva);
            result["offset_in_function"] = target_rva - best_rva;
            result["rva"] = best_rva;
            result["module"] = module_name;
            result["size"] = best_match.value("size", 0);
            result["source"] = best_match.value("source", "");
            result["confidence"] = best_match.value("confidence", 0.0);
            result["name"] = best_match.value("name", "");
            result["is_thunk"] = best_match.value("is_thunk", false);
            result["is_leaf"] = best_match.value("is_leaf", false);

            return CreateSuccessResponse(result.dump());
        }

        json result;
        result["found"] = false;
        result["address"] = FormatAddress(address);
        result["module"] = module_name;
        result["hint"] = "No function found containing this address";

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

} // namespace orpheus::mcp
