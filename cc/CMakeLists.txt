cmake_minimum_required(VERSION 3.20)
project(node_monitor CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# libpqxx is the c++ postgres client; it transitively needs libpq which must come from the system (libpq-dev)
set(SKIP_BUILD_TEST ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    libpqxx
    GIT_REPOSITORY https://github.com/jtv/libpqxx.git
    GIT_TAG 7.10.1
)
FetchContent_MakeAvailable(libpqxx)

include_directories(include)

set(LIB_SOURCES
    src/AlertEngine.cc
    src/CollectorServer.cc
    src/MetricCache.cc
    src/MetricStore.cc
    src/NetflowReceiver.cc
    src/Rule.cc
    src/Scheduler.cc
    src/SocketFd.cc
    src/ThreadPool.cc
)

add_library(node_monitor_lib STATIC ${LIB_SOURCES})
target_link_libraries(node_monitor_lib PUBLIC nlohmann_json::nlohmann_json libpqxx::pqxx)

add_executable(node_monitor src/main.cc)
target_link_libraries(node_monitor PRIVATE node_monitor_lib)
