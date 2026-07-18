if(NOT DEFINED FFC_BUILD_DIR OR NOT DEFINED FFC_SOURCE_DIR OR
   NOT DEFINED FFC_CONFIG OR NOT DEFINED FFC_CPACK_COMMAND)
    message(FATAL_ERROR
        "FFC_BUILD_DIR, FFC_SOURCE_DIR, FFC_CONFIG, and FFC_CPACK_COMMAND are required")
endif()

include("${FFC_BUILD_DIR}/CPackConfig.cmake")
set(runtime_zip
    "${FFC_BUILD_DIR}/${CPACK_PACKAGE_FILE_NAME}-Runtime.zip")
set(symbols_zip
    "${FFC_BUILD_DIR}/${CPACK_PACKAGE_FILE_NAME}-Symbols.zip")
file(REMOVE "${runtime_zip}" "${symbols_zip}")

execute_process(
    COMMAND "${FFC_CPACK_COMMAND}"
        --config "${FFC_BUILD_DIR}/CPackConfig.cmake"
        -C "${FFC_CONFIG}"
        -G ZIP
    WORKING_DIRECTORY "${FFC_BUILD_DIR}"
    RESULT_VARIABLE cpack_result
    OUTPUT_VARIABLE cpack_output
    ERROR_VARIABLE cpack_error
)
if(NOT cpack_result EQUAL 0)
    message(FATAL_ERROR "CPack failed:\n${cpack_output}\n${cpack_error}")
endif()
foreach(archive IN ITEMS "${runtime_zip}" "${symbols_zip}")
    if(NOT EXISTS "${archive}")
        message(FATAL_ERROR "CPack did not create ${archive}")
    endif()
endforeach()

set(extract_dir "${FFC_BUILD_DIR}/test-runtime-archive")
file(REMOVE_RECURSE "${extract_dir}")
file(MAKE_DIRECTORY "${extract_dir}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar xvf "${runtime_zip}"
    WORKING_DIRECTORY "${extract_dir}"
    RESULT_VARIABLE extract_result
    OUTPUT_QUIET
    ERROR_VARIABLE extract_error
)
if(NOT extract_result EQUAL 0)
    message(FATAL_ERROR "Could not extract runtime ZIP: ${extract_error}")
endif()

file(GLOB_RECURSE archive_files
    LIST_DIRECTORIES FALSE
    RELATIVE "${extract_dir}"
    "${extract_dir}/*")
list(SORT archive_files)
set(expected_files
    "AUDIT.md"
    "README.md"
    "SKSE/Plugins/FasterFileCopy.dll"
    "SKSE/Plugins/FasterFileCopy.ini")
list(SORT expected_files)
if(NOT archive_files STREQUAL expected_files)
    message(FATAL_ERROR
        "Runtime ZIP file list differs. Expected '${expected_files}', got '${archive_files}'")
endif()

foreach(relative_file IN ITEMS
    "README.md"
    "AUDIT.md"
    "SKSE/Plugins/FasterFileCopy.ini")
    if(relative_file MATCHES "^SKSE/")
        set(source_file "${FFC_SOURCE_DIR}/FasterFileCopy.ini")
    else()
        set(source_file "${FFC_SOURCE_DIR}/${relative_file}")
    endif()
    file(SHA256 "${source_file}" source_hash)
    file(SHA256 "${extract_dir}/${relative_file}" archive_hash)
    if(NOT source_hash STREQUAL archive_hash)
        message(FATAL_ERROR "Runtime ZIP contains stale ${relative_file}")
    endif()
endforeach()

set(built_dll "${FFC_BUILD_DIR}/${FFC_CONFIG}/FasterFileCopy.dll")
file(SHA256 "${built_dll}" built_dll_hash)
file(SHA256
    "${extract_dir}/SKSE/Plugins/FasterFileCopy.dll" archive_dll_hash)
if(NOT built_dll_hash STREQUAL archive_dll_hash)
    message(FATAL_ERROR "Runtime ZIP contains a stale FasterFileCopy.dll")
endif()

set(symbols_extract_dir "${FFC_BUILD_DIR}/test-symbols-archive")
file(REMOVE_RECURSE "${symbols_extract_dir}")
file(MAKE_DIRECTORY "${symbols_extract_dir}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar xvf "${symbols_zip}"
    WORKING_DIRECTORY "${symbols_extract_dir}"
    RESULT_VARIABLE symbols_extract_result
    OUTPUT_QUIET
    ERROR_VARIABLE symbols_extract_error
)
if(NOT symbols_extract_result EQUAL 0)
    message(FATAL_ERROR
        "Could not extract symbols ZIP: ${symbols_extract_error}")
endif()
file(GLOB_RECURSE symbols_files
    LIST_DIRECTORIES FALSE
    RELATIVE "${symbols_extract_dir}"
    "${symbols_extract_dir}/*")
if(NOT "${symbols_files}" STREQUAL "symbols/FasterFileCopy.pdb")
    message(FATAL_ERROR
        "Symbols ZIP file list differs: '${symbols_files}'")
endif()
file(SHA256 "${FFC_BUILD_DIR}/${FFC_CONFIG}/FasterFileCopy.pdb" built_pdb_hash)
file(SHA256 "${symbols_extract_dir}/symbols/FasterFileCopy.pdb" archive_pdb_hash)
if(NOT built_pdb_hash STREQUAL archive_pdb_hash)
    message(FATAL_ERROR "Symbols ZIP contains a stale FasterFileCopy.pdb")
endif()

message(STATUS "Verified deterministic FasterFileCopy Runtime/Symbols ZIPs")
