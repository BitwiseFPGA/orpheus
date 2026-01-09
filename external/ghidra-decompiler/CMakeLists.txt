# Ghidra Decompiler Library - CMake Build
# Ported from Ghidra/Features/Decompiler/src/decompile/cpp/Makefile
# Apache License 2.0 (NSA/Ghidra)

cmake_minimum_required(VERSION 3.20)
project(ghidra_decompiler VERSION 11.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source directory - local sources included in this folder
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# ============================================================================
# Source File Groups (from Makefile)
# ============================================================================

# Core source files used in all projects
set(CORE_SOURCES
    ${SRC}/xml.cc
    ${SRC}/marshal.cc
    ${SRC}/space.cc
    ${SRC}/float.cc
    ${SRC}/address.cc
    ${SRC}/pcoderaw.cc
    ${SRC}/translate.cc
    ${SRC}/opcodes.cc
    ${SRC}/globalcontext.cc
)

# Additional core files for any projects that decompile
set(DECCORE_SOURCES
    ${SRC}/capability.cc
    ${SRC}/architecture.cc
    ${SRC}/options.cc
    ${SRC}/graph.cc
    ${SRC}/cover.cc
    ${SRC}/block.cc
    ${SRC}/cast.cc
    ${SRC}/typeop.cc
    ${SRC}/database.cc
    ${SRC}/cpool.cc
    ${SRC}/comment.cc
    ${SRC}/stringmanage.cc
    ${SRC}/modelrules.cc
    ${SRC}/fspec.cc
    ${SRC}/action.cc
    ${SRC}/loadimage.cc
    ${SRC}/grammar.cc
    ${SRC}/varnode.cc
    ${SRC}/op.cc
    ${SRC}/type.cc
    ${SRC}/variable.cc
    ${SRC}/varmap.cc
    ${SRC}/jumptable.cc
    ${SRC}/emulate.cc
    ${SRC}/emulateutil.cc
    ${SRC}/flow.cc
    ${SRC}/userop.cc
    ${SRC}/expression.cc
    ${SRC}/multiprecision.cc
    ${SRC}/funcdata.cc
    ${SRC}/funcdata_block.cc
    ${SRC}/funcdata_op.cc
    ${SRC}/funcdata_varnode.cc
    ${SRC}/unionresolve.cc
    ${SRC}/pcodeinject.cc
    ${SRC}/heritage.cc
    ${SRC}/prefersplit.cc
    ${SRC}/rangeutil.cc
    ${SRC}/ruleaction.cc
    ${SRC}/subflow.cc
    ${SRC}/blockaction.cc
    ${SRC}/merge.cc
    ${SRC}/double.cc
    ${SRC}/transform.cc
    ${SRC}/constseq.cc
    ${SRC}/coreaction.cc
    ${SRC}/condexe.cc
    ${SRC}/override.cc
    ${SRC}/dynamic.cc
    ${SRC}/crc32.cc
    ${SRC}/prettyprint.cc
    ${SRC}/printlanguage.cc
    ${SRC}/printc.cc
    ${SRC}/printjava.cc
    ${SRC}/memstate.cc
    ${SRC}/opbehavior.cc
    ${SRC}/paramid.cc
    ${SRC}/signature.cc
)

# Files used for SLEIGH decoder
set(SLEIGH_SOURCES
    ${SRC}/sleigh.cc
    ${SRC}/pcodeparse.cc
    ${SRC}/pcodecompile.cc
    ${SRC}/sleighbase.cc
    ${SRC}/slghsymbol.cc
    ${SRC}/slghpatexpress.cc
    ${SRC}/slghpattern.cc
    ${SRC}/semantics.cc
    ${SRC}/context.cc
    ${SRC}/slaformat.cc
    ${SRC}/compression.cc
    ${SRC}/filemanage.cc
)

# Extra files for library mode (minimal set without console dependencies)
set(EXTRA_SOURCES
    ${SRC}/sleigh_arch.cc
    ${SRC}/inject_sleigh.cc
    ${SRC}/raw_arch.cc
    ${SRC}/xml_arch.cc
    ${SRC}/loadimage_xml.cc
    ${SRC}/libdecomp.cc
    ${SRC}/interface.cc
    ${SRC}/callgraph.cc
)

# Console-specific files (require termios.h on POSIX, skip on Windows)
if(NOT WIN32)
    list(APPEND EXTRA_SOURCES
        ${SRC}/ifacedecomp.cc
        ${SRC}/ifaceterm.cc
        ${SRC}/testfunction.cc
    )
endif()

# ============================================================================
# Yacc/Bison generated files (need to be pre-generated or built)
# ============================================================================

# Check if generated files exist, if not we need bison
set(GENERATED_FILES
    ${SRC}/grammar.cc
    ${SRC}/xml.cc
    ${SRC}/pcodeparse.cc
    ${SRC}/slghparse.cc
)

foreach(genfile ${GENERATED_FILES})
    if(NOT EXISTS ${genfile})
        message(WARNING "Generated file missing: ${genfile}")
        message(STATUS "You may need to run bison/yacc to generate parser files")
    endif()
endforeach()

# ============================================================================
# Library Target
# ============================================================================

set(LIBDECOMP_SOURCES
    ${CORE_SOURCES}
    ${DECCORE_SOURCES}
    ${SLEIGH_SOURCES}
    ${EXTRA_SOURCES}
)

add_library(ghidra_decompiler STATIC ${LIBDECOMP_SOURCES})

target_include_directories(ghidra_decompiler PUBLIC
    ${SRC}
)

# ============================================================================
# Compile Definitions
# ============================================================================

target_compile_definitions(ghidra_decompiler PRIVATE
    # Enable terminal support for interface
    __TERMINAL__
)

# Windows-specific definitions
if(WIN32)
    target_compile_definitions(ghidra_decompiler PRIVATE _WINDOWS)
endif()

# ============================================================================
# Platform-specific settings
# ============================================================================

if(MSVC)
    target_compile_options(ghidra_decompiler PRIVATE
        /W3
        /wd4244  # conversion warnings
        /wd4267  # size_t to int
        /wd4996  # deprecated functions
        /wd4018  # signed/unsigned mismatch
        /utf-8
    )
    target_compile_definitions(ghidra_decompiler PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
    )
else()
    target_compile_options(ghidra_decompiler PRIVATE
        -Wall
        -Wno-sign-compare
    )
endif()

# ============================================================================
# Dependencies
# ============================================================================

# zlib is required for .sla file compression
find_package(ZLIB QUIET)
if(NOT ZLIB_FOUND)
    message(STATUS "ZLIB not found - fetching via FetchContent")
    include(FetchContent)
    FetchContent_Declare(
        zlib
        GIT_REPOSITORY https://github.com/madler/zlib.git
        GIT_TAG        v1.3.1
    )
    set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)
    # Prevent zlib from building shared DLL - we only need static
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(zlib)
    # Use zlibstatic for static linking
    target_link_libraries(ghidra_decompiler PUBLIC zlibstatic)
    # Make zlib headers PUBLIC so consumers can include compression.hh -> zlib.h
    target_include_directories(ghidra_decompiler PUBLIC
        ${zlib_SOURCE_DIR}
        ${zlib_BINARY_DIR}
    )
else()
    target_link_libraries(ghidra_decompiler PRIVATE ZLIB::ZLIB)
endif()

# ============================================================================
# SLEIGH Compiler (optional - for compiling .slaspec to .sla)
# ============================================================================

option(BUILD_SLEIGH_COMPILER "Build the SLEIGH compiler" OFF)

if(BUILD_SLEIGH_COMPILER)
    set(SLEIGH_COMPILER_SOURCES
        ${CORE_SOURCES}
        ${SLEIGH_SOURCES}
        ${SRC}/slgh_compile.cc
        ${SRC}/slghparse.cc
        ${SRC}/slghscan.cc
    )

    add_executable(sleigh ${SLEIGH_COMPILER_SOURCES})
    target_include_directories(sleigh PRIVATE ${SRC})

    if(MSVC)
        target_compile_options(sleigh PRIVATE /W3 /wd4244 /wd4267 /wd4996 /utf-8)
        target_compile_definitions(sleigh PRIVATE _CRT_SECURE_NO_WARNINGS)
    endif()

    if(WIN32)
        target_compile_definitions(sleigh PRIVATE _WINDOWS)
    endif()

    if(ZLIB_FOUND)
        target_link_libraries(sleigh PRIVATE ZLIB::ZLIB)
    else()
        target_link_libraries(sleigh PRIVATE zlibstatic)
        target_include_directories(sleigh PRIVATE ${zlib_SOURCE_DIR} ${zlib_BINARY_DIR})
    endif()
endif()

# ============================================================================
# Installation
# ============================================================================

install(TARGETS ghidra_decompiler
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# Install headers
install(DIRECTORY ${SRC}/
    DESTINATION include/ghidra
    FILES_MATCHING PATTERN "*.hh" PATTERN "*.h"
)

message(STATUS "Ghidra Decompiler Library configured")
message(STATUS "  Source: ${SRC}")
