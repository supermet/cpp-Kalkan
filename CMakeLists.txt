cmake_minimum_required(VERSION 3.22)
project(cppKalkanProject)

set(CMAKE_CXX_STANDARD 17)

add_executable(cppKalkanProject main.cpp httplib/httplib.cc fmt/format.cc)

include_directories(${CMAKE_SOURCE_DIR})
target_link_libraries(cppKalkanProject -L${CMAKE_SOURCE_DIR}/libs -Wl,-rpath -Wl,libs)
