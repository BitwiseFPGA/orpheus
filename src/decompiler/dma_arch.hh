// DMA-based Architecture for Ghidra Decompiler Integration
// Copyright (C) 2025 Orpheus Project
// GPL-3.0 License

#pragma once

#ifdef ORPHEUS_HAS_GHIDRA_DECOMPILER

#include "sleigh_arch.hh"
#include "dma_loadimage.hh"
#include <functional>

namespace orpheus {

/// \brief Architecture implementation that reads code via DMA
///
/// This class provides the bridge between Ghidra's decompiler architecture
/// and Orpheus's DMA memory access system.
class DMAArchitecture : public ghidra::SleighArchitecture {
private:
    DMAReadCallback read_callback_;
    uint64_t base_address_;
    uint64_t image_size_;
    DMALoadImage* dma_loader_;  // Owned by parent (loader member)

public:
    /// Construct a DMA-based architecture
    /// @param target Architecture target (e.g., "x86:LE:64:default")
    /// @param estream Error output stream
    DMAArchitecture(const std::string& target, std::ostream* estream);

    virtual ~DMAArchitecture() {}

    /// Set the DMA read callback before initialization
    void setDMACallback(DMAReadCallback callback) { read_callback_ = std::move(callback); }

    /// Set base address for the image
    void setBaseAddress(uint64_t base) { base_address_ = base; }

    /// Set image size for bounds checking
    void setImageSize(uint64_t size) { image_size_ = size; }

protected:
    /// Build the loader - creates DMALoadImage
    virtual void buildLoader(ghidra::DocumentStorage& store) override;

    /// Resolve architecture from target string
    virtual void resolveArchitecture(void) override;

    /// Post-spec file processing - attach address space
    virtual void postSpecFile(void) override;
};

/// \brief Capability class for DMA architecture (allows registration)
class DMAArchitectureCapability : public ghidra::ArchitectureCapability {
private:
    static DMAArchitectureCapability dmaArchitectureCapability;
    DMAArchitectureCapability(void);
    DMAArchitectureCapability(const DMAArchitectureCapability&) = delete;
    DMAArchitectureCapability& operator=(const DMAArchitectureCapability&) = delete;

public:
    virtual ~DMAArchitectureCapability(void);
    virtual ghidra::Architecture* buildArchitecture(const std::string& filename,
                                                     const std::string& target,
                                                     std::ostream* estream) override;
    virtual bool isFileMatch(const std::string& filename) const override;
    virtual bool isXmlMatch(ghidra::Document* doc) const override;
};

} // namespace orpheus

#endif // ORPHEUS_HAS_GHIDRA_DECOMPILER
