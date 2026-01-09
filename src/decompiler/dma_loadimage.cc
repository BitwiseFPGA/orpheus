// DMA-based LoadImage Implementation
// Copyright (C) 2025 Orpheus Project
// GPL-3.0 License

#ifdef ORPHEUS_HAS_GHIDRA_DECOMPILER

#include "dma_loadimage.hh"
#include <cstring>

namespace orpheus {

DMALoadImage::DMALoadImage(const std::string& name,
                           DMAReadCallback callback,
                           uint64_t base,
                           uint64_t size)
    : ghidra::LoadImage(name)
    , read_callback_(std::move(callback))
    , base_address_(base)
    , image_size_(size)
    , code_space_(nullptr)
    , arch_type_("x86:LE:64:default")  // Default to x86-64 LE
{
}

void DMALoadImage::loadFill(ghidra::uint1* ptr, ghidra::int4 size,
                            const ghidra::Address& addr)
{
    if (!read_callback_) {
        throw ghidra::DataUnavailError("No DMA read callback configured");
    }

    uint64_t offset = addr.getOffset();

    // Optional bounds checking
    if (image_size_ > 0) {
        if (offset < base_address_ || offset >= base_address_ + image_size_) {
            // Address out of image bounds - fill with zeros or throw
            std::memset(ptr, 0, size);
            return;
        }
    }

    // Read via DMA callback
    if (!read_callback_(offset, static_cast<size_t>(size), ptr)) {
        // Read failed - could throw or return zeros
        // For robustness, we'll return zeros and let decompilation continue
        std::memset(ptr, 0, size);
        // Alternatively: throw ghidra::DataUnavailError("DMA read failed at " + addr.getShortcut());
    }
}

std::string DMALoadImage::getArchType(void) const
{
    return arch_type_;
}

void DMALoadImage::adjustVma(long adjust)
{
    // For DMA-based reading, we typically don't need VMA adjustment
    // The addresses we receive are already virtual addresses from the target
    base_address_ += adjust;
}

} // namespace orpheus

#endif // ORPHEUS_HAS_GHIDRA_DECOMPILER
