// DMA-based Architecture Implementation
// Copyright (C) 2025 Orpheus Project
// GPL-3.0 License

#ifdef ORPHEUS_HAS_GHIDRA_DECOMPILER

#include "dma_arch.hh"

namespace orpheus {

// Register the DMA capability (singleton)
DMAArchitectureCapability DMAArchitectureCapability::dmaArchitectureCapability;

DMAArchitectureCapability::DMAArchitectureCapability(void)
{
    name = "dma";
}

DMAArchitectureCapability::~DMAArchitectureCapability(void)
{
}

ghidra::Architecture* DMAArchitectureCapability::buildArchitecture(
    const std::string& filename,
    const std::string& target,
    std::ostream* estream)
{
    return new DMAArchitecture(target, estream);
}

bool DMAArchitectureCapability::isFileMatch(const std::string& filename) const
{
    // Match filenames starting with "dma:" prefix
    return filename.rfind("dma:", 0) == 0;
}

bool DMAArchitectureCapability::isXmlMatch(ghidra::Document* doc) const
{
    return false;  // No XML restore support for DMA
}

// ============================================================================
// DMAArchitecture Implementation
// ============================================================================

DMAArchitecture::DMAArchitecture(const std::string& target, std::ostream* estream)
    : ghidra::SleighArchitecture("dma:memory", target, estream)
    , base_address_(0)
    , image_size_(0xFFFFFFFFFFFFFFFFULL)
    , dma_loader_(nullptr)
{
}

void DMAArchitecture::buildLoader(ghidra::DocumentStorage& store)
{
    collectSpecFiles(*errorstream);

    // Create DMA-based load image
    dma_loader_ = new DMALoadImage("DMA Memory", read_callback_, base_address_, image_size_);
    loader = dma_loader_;
}

void DMAArchitecture::resolveArchitecture(void)
{
    // Use target directly - it's already in the format "x86:LE:64:default"
    archid = getTarget();
    ghidra::SleighArchitecture::resolveArchitecture();
}

void DMAArchitecture::postSpecFile(void)
{
    ghidra::Architecture::postSpecFile();

    // Attach default code space to loader
    if (dma_loader_) {
        dma_loader_->setCodeSpace(getDefaultCodeSpace());
    }
}

} // namespace orpheus

#endif // ORPHEUS_HAS_GHIDRA_DECOMPILER
