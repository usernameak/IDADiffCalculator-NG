cmake_minimum_required(VERSION 3.28)
project(IDADiffCalculator_NG)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 20)

find_package(IDA REQUIRED)

add_ida_module(IDADiffCalculator_NG PLUGIN SOURCES main.cpp)
target_link_libraries(IDADiffCalculator_NG PRIVATE IDA)
target_compile_definitions(IDADiffCalculator_NG PRIVATE _CRT_SECURE_NO_WARNINGS)
