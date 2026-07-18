cmake_minimum_required(VERSION 3.23)

set(NAME "FasterFileCopy")
set(VERSION "1.7.0")

set(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(SOURCE_DIR "${ROOT_DIR}/src")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not supported")
endif()

# vcpkg must be selected before project(). A command-line toolchain always wins;
# the environment/fallback paths are conveniences for local builds only.
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VCPKG_ROOT})
        set(CMAKE_TOOLCHAIN_FILE
            "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE FILEPATH "vcpkg toolchain")
    elseif(EXISTS "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE
            "C:/vcpkg/scripts/buildsystems/vcpkg.cmake"
            CACHE FILEPATH "vcpkg toolchain")
    endif()
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE OR NOT EXISTS "${CMAKE_TOOLCHAIN_FILE}")
    message(FATAL_ERROR "Set CMAKE_TOOLCHAIN_FILE or VCPKG_ROOT to a valid vcpkg installation")
endif()

set(VCPKG_TARGET_TRIPLET "x64-windows-static-md" CACHE STRING "vcpkg target triplet")
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL" CACHE STRING "" FORCE)

project(${NAME} VERSION ${VERSION} LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "FasterFileCopy supports only 64-bit Windows builds with MSVC")
endif()

find_package(CommonLibSSE CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

set(SOURCES
    "${SOURCE_DIR}/ArchiveStream.h"
    "${SOURCE_DIR}/AtomicByteBudget.h"
    "${SOURCE_DIR}/BSAMemoryMap.cpp"
    "${SOURCE_DIR}/BSAMemoryMap.h"
    "${SOURCE_DIR}/CacheFormat.h"
    "${SOURCE_DIR}/CompressedEntryLayout.h"
    "${SOURCE_DIR}/CacheLimitPolicy.h"
    "${SOURCE_DIR}/CacheWarmPolicy.h"
    "${SOURCE_DIR}/CompressedReadPolicy.h"
    "${SOURCE_DIR}/DecompCache.cpp"
    "${SOURCE_DIR}/DecompCache.h"
    "${SOURCE_DIR}/Hooks.cpp"
    "${SOURCE_DIR}/Hooks.h"
    "${SOURCE_DIR}/main.cpp"
    "${SOURCE_DIR}/PCH.h"
    "${SOURCE_DIR}/PESectionSelect.h"
    "${SOURCE_DIR}/PluginInfo.cpp"
    "${SOURCE_DIR}/Settings.h"
    "${SOURCE_DIR}/StreamCursor.h"
)

# Runtime hooks and raw ArchiveStream field offsets are structure-dependent.
# Keep the metadata fail-closed to the three runtimes whose layouts are documented
# in this repository; adding a runtime requires an explicit compatibility test.
add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_23)
target_precompile_headers(${PROJECT_NAME} PRIVATE "${SOURCE_DIR}/PCH.h")
target_include_directories(${PROJECT_NAME} PRIVATE "${SOURCE_DIR}")
target_link_libraries(${PROJECT_NAME} PRIVATE
    CommonLibSSE::CommonLibSSE
    spdlog::spdlog
    Psapi
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    _CRT_SECURE_NO_WARNINGS
    __CMAKE_COMMONLIBSSE_PLUGIN=1
    FFC_VERSION_STRING="${PROJECT_VERSION}"
    FFC_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    FFC_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    FFC_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    SKYRIMSE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

target_compile_options(${PROJECT_NAME} PRIVATE
    /MP
    /W4
    /permissive-
    /Zc:preprocessor
    /Zc:__cplusplus
    /utf-8
    /EHsc
    /external:anglebrackets
    /external:W0
    $<$<CONFIG:Release>:/Zi>
)

target_link_options(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Release>:/DEBUG:FULL>
    $<$<CONFIG:Release>:/OPT:REF>
    $<$<CONFIG:Release>:/OPT:ICF>
)

set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
set_target_properties(${PROJECT_NAME} PROPERTIES
    COMPILE_PDB_NAME "${PROJECT_NAME}"
    PDB_NAME "${PROJECT_NAME}"
)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION "SKSE/Plugins" COMPONENT Runtime
    LIBRARY DESTINATION "SKSE/Plugins"
    COMPONENT Runtime
)
install(FILES "${ROOT_DIR}/FasterFileCopy.ini"
    DESTINATION "SKSE/Plugins"
    COMPONENT Runtime
)
install(FILES
    "${ROOT_DIR}/README.md"
    "${ROOT_DIR}/AUDIT.md"
    DESTINATION "."
    COMPONENT Runtime
)
install(FILES "$<TARGET_PDB_FILE:${PROJECT_NAME}>"
    DESTINATION "symbols"
    OPTIONAL
    COMPONENT Symbols
)

# Standalone loading-screen wall-clock logger for cross-version A/B runs.
add_library(LoadScreenTimer SHARED "${ROOT_DIR}/tools/loadscreentimer/main.cpp")
target_compile_features(LoadScreenTimer PRIVATE cxx_std_23)
target_link_libraries(LoadScreenTimer PRIVATE
    CommonLibSSE::CommonLibSSE
    spdlog::spdlog
)
target_compile_definitions(LoadScreenTimer PRIVATE
    _CRT_SECURE_NO_WARNINGS
    __CMAKE_COMMONLIBSSE_PLUGIN=1
    SKYRIMSE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)
target_compile_options(LoadScreenTimer PRIVATE
    /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8 /EHsc
    /external:anglebrackets /external:W0
)

option(FFC_BUILD_TESTS "Build FasterFileCopy unit tests" ON)
if(FFC_BUILD_TESTS AND EXISTS "${ROOT_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()

set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "FasterFileCopy")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "FasterFileCopy-${PROJECT_VERSION}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL Runtime Symbols)
include(CPack)

message(STATUS "Configured ${PROJECT_NAME} ${PROJECT_VERSION} for ${VCPKG_TARGET_TRIPLET}")
