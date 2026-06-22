cmake_minimum_required(VERSION 3.20)
project(node_monitor CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

set(LIB_SOURCES
    src/collector_server.cc
    src/metric_cache.cc
    src/scheduler.cc
    src/socket_fd.cc
    src/thread_pool.cc
)

add_library(node_monitor_lib STATIC ${LIB_SOURCES})

add_executable(node_monitor src/main.cc)
target_link_libraries(node_monitor PRIVATE node_monitor_lib)
