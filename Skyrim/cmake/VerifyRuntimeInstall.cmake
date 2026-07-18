if(NOT DEFINED FFC_BUILD_DIR OR NOT DEFINED FFC_STAGE_DIR OR NOT DEFINED FFC_CONFIG)
    message(FATAL_ERROR "FFC_BUILD_DIR, FFC_STAGE_DIR and FFC_CONFIG are required")
endif()

file(REMOVE_RECURSE "${FFC_STAGE_DIR}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${FFC_BUILD_DIR}"
        --config "${FFC_CONFIG}"
        --prefix "${FFC_STAGE_DIR}"
        --component Runtime
    RESULT_VARIABLE install_result
    OUTPUT_VARIABLE install_output
    ERROR_VARIABLE install_error
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "Runtime install failed:\n${install_output}\n${install_error}")
endif()

set(plugin_dir "${FFC_STAGE_DIR}/SKSE/Plugins")
foreach(required_file FasterFileCopy.dll FasterFileCopy.ini)
    if(NOT EXISTS "${plugin_dir}/${required_file}")
        message(FATAL_ERROR "Runtime package is missing SKSE/Plugins/${required_file}")
    endif()
endforeach()
foreach(required_doc README.md AUDIT.md)
    if(NOT EXISTS "${FFC_STAGE_DIR}/${required_doc}")
        message(FATAL_ERROR "Runtime package is missing ${required_doc}")
    endif()
endforeach()

foreach(forbidden_file
    BSAMemoryMap.dll
    BSAMemoryMap.ini
    dstorage.dll
    dstoragecore.dll)
    if(EXISTS "${plugin_dir}/${forbidden_file}")
        message(FATAL_ERROR "Runtime package contains forbidden legacy/experimental file: ${forbidden_file}")
    endif()
endforeach()

file(STRINGS "${plugin_dir}/FasterFileCopy.ini" ini_lines)

function(require_general_setting required_key expected_value)
    set(in_general FALSE)
    set(match_count 0)
    set(actual_value "")
    foreach(raw_line IN LISTS ini_lines)
        string(STRIP "${raw_line}" line)
        if(line MATCHES "^\\[([^]]+)\\]$")
            string(TOLOWER "${CMAKE_MATCH_1}" section_name)
            if(section_name STREQUAL "general")
                set(in_general TRUE)
            else()
                set(in_general FALSE)
            endif()
        elseif(in_general AND NOT line MATCHES "^[;#]" AND
               line MATCHES "^([^=]+)=(.*)$")
            string(STRIP "${CMAKE_MATCH_1}" candidate_key)
            string(TOLOWER "${candidate_key}" candidate_key)
            string(TOLOWER "${required_key}" required_key_lower)
            if(candidate_key STREQUAL required_key_lower)
                math(EXPR match_count "${match_count} + 1")
                string(STRIP "${CMAKE_MATCH_2}" actual_value)
            endif()
        endif()
    endforeach()
    if(NOT match_count EQUAL 1 OR NOT actual_value STREQUAL expected_value)
        message(FATAL_ERROR
            "Canonical [General] must contain exactly one active ${required_key}=${expected_value}; found count=${match_count}, value='${actual_value}'")
    endif()
endfunction()

require_general_setting("bEnableMmap" "1")
require_general_setting("bEnableDecompCache" "1")
require_general_setting("iDecompCacheMode" "1")
require_general_setting("iDecompCacheMaxMB" "0")

foreach(raw_line IN LISTS ini_lines)
    string(STRIP "${raw_line}" line)
    string(TOLOWER "${line}" line_lower)
    if(line_lower STREQUAL "[modec]")
        message(FATAL_ERROR "Canonical INI contains retired [ModeC] settings")
    endif()
endforeach()

message(STATUS "Verified deterministic FasterFileCopy runtime install")
