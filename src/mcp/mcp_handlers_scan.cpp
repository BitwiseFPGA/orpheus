/**
 * MCP Handlers - Scanning
 *
 * Pattern and string scanning handlers:
 * - HandleScanPattern
 * - HandleScanStrings
 * - HandleFindXrefs
 */

#include "mcp_server.h"
#include "ui/application.h"
#include "core/dma_interface.h"
#include "analysis/pattern_scanner.h"
#include "analysis/string_scanner.h"

#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace orpheus::mcp {

std::string MCPServer::HandleScanPattern(const std::string& body) {
    try {
        auto req = json::parse(body);
        uint32_t pid = req["pid"];
        uint64_t base = std::stoull(req["base"].get<std::string>(), nullptr, 16);
        uint32_t size = req["size"];
        std::string pattern = req["pattern"];

        // Validate parameters
        if (pattern.empty()) {
            return CreateErrorResponse("Invalid pattern: pattern string is empty");
        }
        if (base == 0) {
            return CreateErrorResponse("Invalid base address: cannot scan from NULL (0x0)");
        }
        if (size == 0) {
            return CreateErrorResponse("Invalid size: cannot scan 0 bytes");
        }
        if (size > 512 * 1024 * 1024) {  // 512MB limit
            return CreateErrorResponse("Size too large: maximum scan region is 512MB");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected - check hardware connection");
        }

        // Verify process exists
        auto proc_info = dma->GetProcessInfo(pid);
        if (!proc_info) {
            return CreateErrorResponse("Process not found: PID " + std::to_string(pid) + " does not exist or has terminated");
        }

        auto compiled = analysis::PatternScanner::Compile(pattern);
        if (!compiled) {
            return CreateErrorResponse("Invalid pattern syntax: '" + pattern + "' - use IDA-style format like '48 8B ?? 74 ?? ?? ?? ??' where ?? are wildcards");
        }

        auto data = dma->ReadMemory(pid, base, size);
        if (data.empty()) {
            std::stringstream err;
            err << "Failed to read scan region at " << FormatAddress(base)
                << " (size: " << size << " bytes) - region may be unmapped or protected";
            return CreateErrorResponse(err.str());
        }

        auto results = analysis::PatternScanner::Scan(data, *compiled, base, 100);

        json result;
        result["pattern"] = pattern;
        result["base"] = req["base"];
        result["count"] = results.size();

        json addresses = json::array();
        for (uint64_t addr : results) {
            std::stringstream ss;
            ss << "0x" << std::hex << addr;
            addresses.push_back(ss.str());
        }
        result["addresses"] = addresses;

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleScanStrings(const std::string& body) {
    try {
        auto req = json::parse(body);
        uint32_t pid = req["pid"];
        uint64_t base = std::stoull(req["base"].get<std::string>(), nullptr, 16);
        uint32_t size = req["size"];
        int min_length = req.value("min_length", 4);

        // Validate parameters
        if (base == 0) {
            return CreateErrorResponse("Invalid base address: cannot scan from NULL (0x0)");
        }
        if (size == 0) {
            return CreateErrorResponse("Invalid size: cannot scan 0 bytes");
        }
        if (size > 512 * 1024 * 1024) {  // 512MB limit
            return CreateErrorResponse("Size too large: maximum scan region is 512MB");
        }
        if (min_length < 1 || min_length > 256) {
            return CreateErrorResponse("Invalid min_length: must be between 1 and 256");
        }

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected - check hardware connection");
        }

        // Verify process exists
        auto proc_info = dma->GetProcessInfo(pid);
        if (!proc_info) {
            return CreateErrorResponse("Process not found: PID " + std::to_string(pid) + " does not exist or has terminated");
        }

        auto data = dma->ReadMemory(pid, base, size);
        if (data.empty()) {
            std::stringstream err;
            err << "Failed to read scan region at " << FormatAddress(base)
                << " (size: " << size << " bytes) - region may be unmapped or protected";
            return CreateErrorResponse(err.str());
        }

        analysis::StringScanOptions opts;
        opts.min_length = min_length;

        auto results = analysis::StringScanner::Scan(data, opts, base);

        json result;
        result["base"] = req["base"];
        result["count"] = results.size();

        json strings = json::array();
        for (const auto& str : results) {
            json s;
            std::stringstream ss;
            ss << "0x" << std::hex << str.address;
            s["address"] = ss.str();
            s["value"] = str.value;
            s["type"] = str.type == analysis::StringType::ASCII ? "ASCII" : "UTF16";
            strings.push_back(s);
        }
        result["strings"] = strings;

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

std::string MCPServer::HandleFindXrefs(const std::string& body) {
    try {
        auto req = json::parse(body);
        uint32_t pid = req["pid"];
        uint64_t target = std::stoull(req["target"].get<std::string>(), nullptr, 16);
        uint64_t base = std::stoull(req["base"].get<std::string>(), nullptr, 16);
        uint32_t size = req["size"];
        int max_results = req.value("max_results", 100);

        auto* dma = app_->GetDMA();
        if (!dma || !dma->IsConnected()) {
            return CreateErrorResponse("DMA not connected");
        }

        auto data = dma->ReadMemory(pid, base, size);
        if (data.empty()) {
            return CreateErrorResponse("Failed to read memory");
        }

        json result;
        result["target"] = req["target"];
        result["base"] = req["base"];

        json xrefs = json::array();

        // Scan for direct references (little-endian 64-bit pointers)
        for (size_t i = 0; i + 8 <= data.size() && (int)xrefs.size() < max_results; i++) {
            uint64_t val = *reinterpret_cast<uint64_t*>(&data[i]);
            if (val == target) {
                json ref;
                uint64_t ref_addr = base + i;
                ref["address"] = FormatAddress(ref_addr);
                ref["type"] = "ptr64";
                ref["context"] = FormatAddressWithContext(pid, ref_addr);
                xrefs.push_back(ref);
            }
        }

        // Scan for 32-bit relative offsets (common in x64 RIP-relative addressing)
        for (size_t i = 0; i + 4 <= data.size() && (int)xrefs.size() < max_results; i++) {
            int32_t rel = *reinterpret_cast<int32_t*>(&data[i]);
            uint64_t computed = base + i + 4 + rel;  // RIP + 4 + offset
            if (computed == target) {
                json ref;
                uint64_t ref_addr = base + i;
                ref["address"] = FormatAddress(ref_addr);
                ref["type"] = "rel32";
                ref["context"] = FormatAddressWithContext(pid, ref_addr);
                xrefs.push_back(ref);
            }
        }

        result["count"] = xrefs.size();
        result["xrefs"] = xrefs;

        return CreateSuccessResponse(result.dump());

    } catch (const std::exception& e) {
        return CreateErrorResponse(std::string("Error: ") + e.what());
    }
}

} // namespace orpheus::mcp
