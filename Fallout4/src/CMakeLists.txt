# ── CommonLibF4 multi-runtime source build ───────────────────────────────────

macro(find_commonlib_path)
    if(CommonLibName AND NOT ${CommonLibName} STREQUAL "")
        find_path(CommonLibPath
            include/REL/Relocation.h
            PATHS ${ROOT_DIR}/external/${CommonLibName}/${CommonLibName}/)
        if(${CommonLibPath} STREQUAL "CommonLibPath-NOTFOUND")
            set_from_environment(${CommonLibName}Path)
            set(CommonLibPath ${${CommonLibName}Path})
        endif()
    endif()
endmacro()

set(CommonLibName "CommonLibF4")
set_root_directory()

find_commonlib_path()
message(STATUS "Building ${PROJECT_NAME} ${PROJECT_VERSION} with ${CommonLibName} at ${CommonLibPath}.")

set(SOURCE_DIR "${ROOT_DIR}/src")
set(SOURCE_FILES
    "${SOURCE_DIR}/main.cpp"
    "${SOURCE_DIR}/PCH.cpp"
    "${SOURCE_DIR}/PCH.h"
    "${SOURCE_DIR}/Settings.h"
    "${SOURCE_DIR}/BA2MemoryMap.h"
    "${SOURCE_DIR}/BA2MemoryMap.cpp"
    "${SOURCE_DIR}/DecompCache.h"
    "${SOURCE_DIR}/DecompCache.cpp"
    "${SOURCE_DIR}/FastCopy.h"
    "${SOURCE_DIR}/MmapStream.h"
    "${SOURCE_DIR}/MmapStream.cpp"
    "${SOURCE_DIR}/Hooks.h"
    "${SOURCE_DIR}/Hooks.cpp"
)

source_group(TREE "${ROOT_DIR}" FILES ${SOURCE_FILES})

set(VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/src/Plugin.h")
configure_file(
    "${ROOT_DIR}/cmake/Plugin.h.in"
    "${VERSION_HEADER}"
    @ONLY
)
source_group("src" FILES "${VERSION_HEADER}")

configure_file(
    "${ROOT_DIR}/cmake/version.rc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.rc"
    @ONLY
)

add_library(
    "${PROJECT_NAME}"
    SHARED
    ${SOURCE_FILES}
    "${VERSION_HEADER}"
    "${CMAKE_CURRENT_BINARY_DIR}/version.rc"
    "${ROOT_DIR}/.clang-format"
    "${ROOT_DIR}/.editorconfig"
)

target_compile_features("${PROJECT_NAME}" PRIVATE cxx_std_23)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    target_compile_options("${PROJECT_NAME}" PRIVATE
        "/EHa" "/sdl" "/utf-8" "/Zi"
        "/permissive-" "/Zc:preprocessor"
        "/arch:AVX2"  # FastCopyLarge uses _mm256_stream_si256 / _mm256_loadu_si256
        "/wd4324"
        "$<$<CONFIG:DEBUG>:>"
        "$<$<CONFIG:RELEASE>:/Zc:inline;/JMC-;/Ob3>"
    )
    target_link_options("${PROJECT_NAME}" PRIVATE
        "$<$<CONFIG:DEBUG>:/INCREMENTAL;/OPT:NOREF;/OPT:NOICF>"
        "$<$<CONFIG:RELEASE>:/INCREMENTAL:NO;/OPT:REF;/OPT:ICF;/DEBUG:FULL>"
    )
endif()

target_include_directories("${PROJECT_NAME}" PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/src"
    "${SOURCE_DIR}"
)

if(DEFINED CommonLibPath AND NOT ${CommonLibPath} STREQUAL "" AND IS_DIRECTORY ${CommonLibPath})
    add_subdirectory(${CommonLibPath} ${CommonLibName})
else()
    message(FATAL_ERROR "Variable ${CommonLibName}Path is not set or in external/.")
endif()

find_package(fmt REQUIRED CONFIG)
find_package(spdlog REQUIRED CONFIG)
find_package(mmio REQUIRED CONFIG)
find_package(xbyak REQUIRED CONFIG)
find_package(ZLIB REQUIRED)
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
add_compile_definitions(_SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING)

target_include_directories("${PROJECT_NAME}" PRIVATE ${DETOURS_INCLUDE_DIRS})

target_link_libraries("${PROJECT_NAME}" PRIVATE
    CommonLibF4::CommonLibF4
    mmio::mmio
    ${DETOURS_LIBRARY}
    fmt::fmt
    xbyak::xbyak
    ZLIB::ZLIB
)

target_compile_definitions("${PROJECT_NAME}" PRIVATE F4SE_SUPPORT_XBYAK)
target_compile_definitions(CommonLibF4 PUBLIC F4SE_SUPPORT_XBYAK _SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING)

target_precompile_headers("${PROJECT_NAME}" PRIVATE "${SOURCE_DIR}/PCH.h")

handle_data_files(
    FILES
    "$<TARGET_FILE:${PROJECT_NAME}>"
    "${ROOT_DIR}/data/Data/F4SE/Plugins/FasterFileCopyFO4.ini"
    DESTINATION "F4SE/Plugins"
)

# ── MO2 auto-deploy ─────────────────────────────────────────────────────────
foreach(DEPLOY_TARGET $ENV{FalloutPluginTargets})
    message("Adding deployment target ${DEPLOY_TARGET}.")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> "${DEPLOY_TARGET}/F4SE/Plugins/")
endforeach()

# ── Zip packaging ────────────────────────────────────────────────────────────
set(ZIP_DIR "${CMAKE_CURRENT_BINARY_DIR}/zip")
add_custom_target(build-time-make-directory ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${ZIP_DIR}" "${ZIP_DIR}/F4SE/Plugins/")
file(MAKE_DIRECTORY "${ZIP_DIR}/F4SE/Plugins/")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> "${ZIP_DIR}/F4SE/Plugins/")

set(TARGET_ZIP "${PROJECT_NAME}-${PROJECT_VERSION}.7z")
ADD_CUSTOM_COMMAND(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_ZIP} --format=7zip -- .
    WORKING_DIRECTORY ${ZIP_DIR})
