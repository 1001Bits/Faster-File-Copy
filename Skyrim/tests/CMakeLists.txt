add_executable(FFCStreamCursorTests StreamCursorTests.cpp)
target_compile_features(FFCStreamCursorTests PRIVATE cxx_std_23)
target_include_directories(FFCStreamCursorTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCStreamCursorTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME StreamCursor COMMAND FFCStreamCursorTests)

add_executable(FFCPESectionSelectTests PESectionSelectTests.cpp)
target_compile_features(FFCPESectionSelectTests PRIVATE cxx_std_23)
target_include_directories(FFCPESectionSelectTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCPESectionSelectTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME PESectionSelect COMMAND FFCPESectionSelectTests)

add_executable(FFCAtomicByteBudgetTests AtomicByteBudgetTests.cpp)
target_compile_features(FFCAtomicByteBudgetTests PRIVATE cxx_std_23)
target_include_directories(FFCAtomicByteBudgetTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCAtomicByteBudgetTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME AtomicByteBudget COMMAND FFCAtomicByteBudgetTests)

add_executable(FFCCompressedReadPolicyTests CompressedReadPolicyTests.cpp)
target_compile_features(FFCCompressedReadPolicyTests PRIVATE cxx_std_23)
target_include_directories(FFCCompressedReadPolicyTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCCompressedReadPolicyTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME CompressedReadPolicy COMMAND FFCCompressedReadPolicyTests)

add_executable(FFCCompressedEntryLayoutTests CompressedEntryLayoutTests.cpp)
target_compile_features(FFCCompressedEntryLayoutTests PRIVATE cxx_std_23)
target_include_directories(FFCCompressedEntryLayoutTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCCompressedEntryLayoutTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME CompressedEntryLayout COMMAND FFCCompressedEntryLayoutTests)

add_executable(FFCCacheLimitPolicyTests CacheLimitPolicyTests.cpp)
target_compile_features(FFCCacheLimitPolicyTests PRIVATE cxx_std_23)
target_include_directories(FFCCacheLimitPolicyTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCCacheLimitPolicyTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME CacheLimitPolicy COMMAND FFCCacheLimitPolicyTests)

add_executable(FFCCacheWarmPolicyTests CacheWarmPolicyTests.cpp)
target_compile_features(FFCCacheWarmPolicyTests PRIVATE cxx_std_23)
target_include_directories(FFCCacheWarmPolicyTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
if(MSVC)
    target_compile_options(FFCCacheWarmPolicyTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
endif()
add_test(NAME CacheWarmPolicy COMMAND FFCCacheWarmPolicyTests)

add_test(NAME RuntimeInstallLayout
    COMMAND "${CMAKE_COMMAND}"
        -DFFC_BUILD_DIR=${CMAKE_BINARY_DIR}
        -DFFC_STAGE_DIR=${CMAKE_BINARY_DIR}/test-runtime-install
        -DFFC_CONFIG=$<CONFIG>
        -P "${PROJECT_SOURCE_DIR}/cmake/VerifyRuntimeInstall.cmake"
)

add_test(NAME RuntimeArchiveLayout
    COMMAND "${CMAKE_COMMAND}"
        -DFFC_BUILD_DIR=${CMAKE_BINARY_DIR}
        -DFFC_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -DFFC_CONFIG=$<CONFIG>
        -DFFC_CPACK_COMMAND=${CMAKE_CPACK_COMMAND}
        -P "${PROJECT_SOURCE_DIR}/cmake/VerifyRuntimeArchive.cmake"
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/CacheFormatTests.cpp")
    add_executable(FFCCacheFormatTests CacheFormatTests.cpp)
    target_compile_features(FFCCacheFormatTests PRIVATE cxx_std_23)
    target_include_directories(FFCCacheFormatTests PRIVATE "${PROJECT_SOURCE_DIR}/src")
    if(MSVC)
        target_compile_options(FFCCacheFormatTests PRIVATE /W4 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8)
    endif()
    add_test(NAME CacheFormat COMMAND FFCCacheFormatTests)
endif()
