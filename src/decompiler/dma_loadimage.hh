// DMA-based LoadImage for Ghidra Decompiler Integration
// Copyright (C) 2025 Orpheus Project
// GPL-3.0 License

#pragma once

#ifdef ORPHEUS_HAS_GHIDRA_DECOMPILER

#include "loadimage.hh"
#include <functional>
#include <cstdint>

namespace orpheus {

/// Callback type for reading memory from DMA
/// @param addr Virtual address to read from
/// @param size Number of bytes to read
/// @param buffer Output buffer (pre-allocated)
/// @return true if read succeeded
using DMAReadCallback = std::function<bool(uint64_t addr, size_t size, uint8_t* buffer)>;

/// \brief LoadImage implementation that reads from DMA memory
///
/// This class provides the bridge between Ghidra's decompiler and
/// Orpheus's DMA memory access. It implements the LoadImage interface
/// to supply code bytes on-demand during decompilation.
class DMALoadImage : public ghidra::LoadImage {
private:
    DMAReadCallback read_callback_;
    uint64_t base_address_;
    uint64_t image_size_;
    ghidra::AddrSpace* code_space_;
    std::string arch_type_;

public:
    /// Construct a DMA-based load image
    /// @param name Display name for the image
    /// @param callback Function to read memory via DMA
    /// @param base Base address of the code region
    /// @param size Size of the code region (for bounds checking)
    DMALoadImage(const std::string& name,
                 DMAReadCallback callback,
                 uint64_t base = 0,
                 uint64_t size = 0xFFFFFFFFFFFFFFFFULL);

    virtual ~DMALoadImage() = default;

    /// Set the address space for code
    void setCodeSpace(ghidra::AddrSpace* space) { code_space_ = space; }

    /// Set architecture type string (e.g., "x86:LE:64:default")
    void setArchType(const std::string& arch) { arch_type_ = arch; }

    /// Set base address for the image
    void setBaseAddress(uint64_t base) { base_address_ = base; }

    /// Set image size for bounds checking
    void setImageSize(uint64_t size) { image_size_ = size; }

    // ========================================================================
    // LoadImage Interface Implementation
    // ========================================================================

    /// Load bytes from memory via DMA
    /// @param ptr Output buffer for bytes
    /// @param size Number of bytes to read
    /// @param addr Address to read from
    /// @throws DataUnavailError if read fails
    virtual void loadFill(ghidra::uint1* ptr, ghidra::int4 size,
                          const ghidra::Address& addr) override;

    /// Get architecture type string
    /// @return Architecture identifier (e.g., "x86:LE:64:default")
    virtual std::string getArchType(void) const override;

    /// Adjust virtual memory addresses (no-op for DMA)
    /// @param adjust Offset to add to addresses
    virtual void adjustVma(long adjust) override;

    // Optional: Symbol support (can be extended later)
    // virtual void openSymbols(void) const override;
    // virtual bool getNextSymbol(ghidra::LoadImageFunc& record) const override;
    // virtual void closeSymbols(void) const override;
};

} // namespace orpheus

#endif // ORPHEUS_HAS_GHIDRA_DECOMPILER
