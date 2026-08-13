cmake_minimum_required(VERSION 3.20)
project(veloce_agent VERSION 1.0.0 LANGUAGES CXX)

set(VELOCE_FIPS_INCLUDE "" CACHE PATH "Headers matching the native FIPS library")
set(VELOCE_PQC_INCLUDE "" CACHE PATH "wolfSSL public-tree headers matching the PQC provider")
set(VELOCE_PQC_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/pqc"
    CACHE PATH "Directory containing the PQC user_settings.h")

if(NOT IS_DIRECTORY "${VELOCE_FIPS_INCLUDE}")
    message(FATAL_ERROR "Set VELOCE_FIPS_INCLUDE to the matching native FIPS headers")
endif()
if(NOT IS_DIRECTORY "${VELOCE_PQC_INCLUDE}")
    message(FATAL_ERROR "Set VELOCE_PQC_INCLUDE to the matching PQC provider headers")
endif()

add_library(veloce_agent_main OBJECT src/main.cpp)
add_library(veloce_fips_core OBJECT src/fips_core.cpp)
add_library(veloce_pqc_core OBJECT src/pqc_core.cpp)

foreach(target veloce_agent_main veloce_fips_core veloce_pqc_core)
    target_compile_features(${target} PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /O2)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -O2)
    endif()
    if(WIN32)
        target_compile_definitions(${target} PRIVATE _WIN32_WINNT=0x0602)
    endif()
endforeach()

target_include_directories(veloce_fips_core PRIVATE "${VELOCE_FIPS_INCLUDE}")
target_include_directories(veloce_pqc_core PRIVATE
    "${VELOCE_PQC_CONFIG}" "${VELOCE_PQC_INCLUDE}")
target_compile_definitions(veloce_pqc_core PRIVATE WOLFSSL_USER_SETTINGS)

add_executable(veloce-agent
    $<TARGET_OBJECTS:veloce_agent_main>
    $<TARGET_OBJECTS:veloce_fips_core>
    $<TARGET_OBJECTS:veloce_pqc_core>)
find_package(Threads REQUIRED)
target_link_libraries(veloce-agent PRIVATE Threads::Threads)
if(WIN32)
    target_link_libraries(veloce-agent PRIVATE advapi32)
elseif(CMAKE_DL_LIBS)
    target_link_libraries(veloce-agent PRIVATE ${CMAKE_DL_LIBS})
endif()

install(TARGETS veloce-agent RUNTIME DESTINATION bin)
