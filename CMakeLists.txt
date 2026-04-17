cmake_minimum_required(VERSION 3.16)
project(firmhead VERSION 0.1.0 DESCRIPTION "Firmware container headers: parse, verify checksums and audit signing" LANGUAGES C)

option(FIRMHEAD_BUILD_TESTS "Build tests" OFF)
option(FIRMHEAD_BUILD_EXAMPLES "Build examples" OFF)
option(FIRMHEAD_BUILD_FUZZ "Build libFuzzer targets" OFF)
option(FIRMHEAD_BUILD_BENCH "Build benchmarks" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_library(firmhead src/image.c src/hash.c src/formats.c src/vendor.c src/fdt.c src/audit.c)
add_library(firmhead::firmhead ALIAS firmhead)
target_include_directories(firmhead PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(firmhead PROPERTIES
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

set(PC_CFLAGS "")
if(BUILD_SHARED_LIBS)
    target_compile_definitions(firmhead PRIVATE FWH_BUILD_SHARED INTERFACE FWH_SHARED)
    set(PC_CFLAGS "-DFWH_SHARED")
endif()

install(TARGETS firmhead EXPORT firmheadTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT firmheadTargets
    NAMESPACE firmhead::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/firmhead)

configure_package_config_file(cmake/firmheadConfig.cmake.in
    ${PROJECT_BINARY_DIR}/firmheadConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/firmhead)
write_basic_package_version_file(${PROJECT_BINARY_DIR}/firmheadConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${PROJECT_BINARY_DIR}/firmheadConfig.cmake
    ${PROJECT_BINARY_DIR}/firmheadConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/firmhead)

configure_file(firmhead.pc.in ${PROJECT_BINARY_DIR}/firmhead.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/firmhead.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

if(FIRMHEAD_BUILD_TESTS)
    enable_testing()
    add_executable(test_firmhead tests/test_firmhead.c)
    target_link_libraries(test_firmhead PRIVATE firmhead)
    target_compile_definitions(test_firmhead PRIVATE FWH_TEST_DATA="${PROJECT_SOURCE_DIR}/tests/data")
    add_test(NAME firmhead COMMAND test_firmhead)
    add_executable(test_limits tests/test_limits.c)
    target_link_libraries(test_limits PRIVATE firmhead)
    target_compile_definitions(test_limits PRIVATE FWH_TEST_DATA="${PROJECT_SOURCE_DIR}/tests/data"
        FWH_TEST_FIT_CEILING=8388608)
    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        target_link_libraries(test_limits PRIVATE ZLIB::ZLIB)
        target_compile_definitions(test_limits PRIVATE FWH_TEST_ZLIB)
    endif()
    add_test(NAME limits COMMAND test_limits)
    add_library(firmhead_header_check OBJECT tests/header_check.c)
    target_include_directories(firmhead_header_check PRIVATE include)
endif()

if(FIRMHEAD_BUILD_EXAMPLES)
    add_executable(firmhead-info examples/firmhead-info.c)
    target_link_libraries(firmhead-info PRIVATE firmhead)
endif()

if(FIRMHEAD_BUILD_FUZZ)
    add_executable(fuzz_open fuzz/fuzz_open.c)
    target_link_libraries(fuzz_open PRIVATE firmhead)
    target_link_options(fuzz_open PRIVATE -fsanitize=fuzzer)
endif()

if(FIRMHEAD_BUILD_BENCH)
    add_executable(firmhead_bench bench/bench.c)
    target_link_libraries(firmhead_bench PRIVATE firmhead)
endif()
