#pragma once

#include <cstdint>
#include <cstring>
#include <vector>
#include <optional>
#include <string>

namespace orpheus {
namespace utils {

/**
 * MemoryReader - Typed memory reading utilities
 *
 * Wraps raw DMA reads with type-safe accessor methods.
 * Eliminates repeated pattern of ReadMemory + size check + memcpy.
 */
class MemoryReader {
public:
    using ReadFunc = std::function<std::vector<uint8_t>(uint64_t addr, size_t size)>;

    explicit MemoryReader(ReadFunc read_fn) : read_fn_(std::move(read_fn)) {}

    // Primitive type readers - return std::nullopt on failure
    std::optional<uint8_t> ReadU8(uint64_t addr) {
        auto data = read_fn_(addr, 1);
        if (data.size() < 1) return std::nullopt;
        return data[0];
    }

    std::optional<int8_t> ReadI8(uint64_t addr) {
        auto data = read_fn_(addr, 1);
        if (data.size() < 1) return std::nullopt;
        return static_cast<int8_t>(data[0]);
    }

    std::optional<uint16_t> ReadU16(uint64_t addr) {
        auto data = read_fn_(addr, 2);
        if (data.size() < 2) return std::nullopt;
        uint16_t v;
        std::memcpy(&v, data.data(), 2);
        return v;
    }

    std::optional<int16_t> ReadI16(uint64_t addr) {
        auto data = read_fn_(addr, 2);
        if (data.size() < 2) return std::nullopt;
        int16_t v;
        std::memcpy(&v, data.data(), 2);
        return v;
    }

    std::optional<uint32_t> ReadU32(uint64_t addr) {
        auto data = read_fn_(addr, 4);
        if (data.size() < 4) return std::nullopt;
        uint32_t v;
        std::memcpy(&v, data.data(), 4);
        return v;
    }

    std::optional<int32_t> ReadI32(uint64_t addr) {
        auto data = read_fn_(addr, 4);
        if (data.size() < 4) return std::nullopt;
        int32_t v;
        std::memcpy(&v, data.data(), 4);
        return v;
    }

    std::optional<uint64_t> ReadU64(uint64_t addr) {
        auto data = read_fn_(addr, 8);
        if (data.size() < 8) return std::nullopt;
        uint64_t v;
        std::memcpy(&v, data.data(), 8);
        return v;
    }

    std::optional<int64_t> ReadI64(uint64_t addr) {
        auto data = read_fn_(addr, 8);
        if (data.size() < 8) return std::nullopt;
        int64_t v;
        std::memcpy(&v, data.data(), 8);
        return v;
    }

    std::optional<float> ReadFloat(uint64_t addr) {
        auto data = read_fn_(addr, 4);
        if (data.size() < 4) return std::nullopt;
        float v;
        std::memcpy(&v, data.data(), 4);
        return v;
    }

    std::optional<double> ReadDouble(uint64_t addr) {
        auto data = read_fn_(addr, 8);
        if (data.size() < 8) return std::nullopt;
        double v;
        std::memcpy(&v, data.data(), 8);
        return v;
    }

    // Alias for pointer reading
    std::optional<uint64_t> ReadPtr(uint64_t addr) {
        return ReadU64(addr);
    }

    /**
     * Read a null-terminated string up to max_len bytes
     */
    std::optional<std::string> ReadString(uint64_t addr, size_t max_len = 256) {
        auto data = read_fn_(addr, max_len);
        if (data.empty()) return std::nullopt;

        // Find null terminator
        size_t str_len = 0;
        for (size_t i = 0; i < data.size(); i++) {
            if (data[i] == '\0') break;
            str_len++;
        }

        return std::string(reinterpret_cast<const char*>(data.data()), str_len);
    }

    /**
     * Read a fixed-size buffer
     */
    std::vector<uint8_t> ReadBytes(uint64_t addr, size_t size) {
        return read_fn_(addr, size);
    }

    /**
     * Read and interpret as a struct (POD types only)
     */
    template<typename T>
    std::optional<T> ReadStruct(uint64_t addr) {
        static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
        auto data = read_fn_(addr, sizeof(T));
        if (data.size() < sizeof(T)) return std::nullopt;
        T v;
        std::memcpy(&v, data.data(), sizeof(T));
        return v;
    }

    /**
     * Follow a pointer and read value at destination
     */
    template<typename T>
    std::optional<T> ReadPtrTo(uint64_t ptr_addr) {
        auto ptr = ReadPtr(ptr_addr);
        if (!ptr || *ptr == 0) return std::nullopt;
        return ReadStruct<T>(*ptr);
    }

    /**
     * Read RIP-relative offset and resolve to absolute address
     * instruction_addr: address of the instruction containing the offset
     * offset_position: offset from instruction start where the 4-byte offset is located
     * instruction_size: total size of the instruction (default 7 for LEA/MOV)
     */
    std::optional<uint64_t> ReadRipRelative(uint64_t instruction_addr,
                                             size_t offset_position = 3,
                                             size_t instruction_size = 7) {
        auto offset = ReadI32(instruction_addr + offset_position);
        if (!offset) return std::nullopt;
        return instruction_addr + instruction_size + *offset;
    }

private:
    ReadFunc read_fn_;
};

/**
 * Helper to create a MemoryReader from a DMA instance and PID
 */
template<typename DMA>
MemoryReader MakeReader(DMA* dma, uint32_t pid) {
    return MemoryReader([dma, pid](uint64_t addr, size_t size) {
        return dma->ReadMemory(pid, addr, static_cast<uint32_t>(size));
    });
}

} // namespace utils
} // namespace orpheus
