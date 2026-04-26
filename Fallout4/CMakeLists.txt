cmake_minimum_required(VERSION 3.23)
set(NAME "FasterFileCopyFO4")
set(VERSION 1.1.0)

# ── Project setup (based on Daytripper4 multi-runtime pattern) ──────────────
project(
    ${NAME}
    VERSION ${VERSION}
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
    message(FATAL_ERROR "in-source builds are not allowed")
endif()

include(cmake/common.cmake)

add_subdirectory(src)
include(cmake/packaging.cmake)

# Disable C++ modules in MSVC IDE (avoids STL modules build issues)
if(MSVC_VERSION GREATER_EQUAL 1936 AND MSVC_IDE)
    file(CONFIGURE OUTPUT "${CMAKE_BINARY_DIR}/Directory.Build.props" CONTENT [==[
<Project>
  <ItemDefinitionGroup>
    <ClCompile>
      <BuildStlModules>false</BuildStlModules>
    </ClCompile>
  </ItemDefinitionGroup>
</Project>
]==] @ONLY)
endif()
