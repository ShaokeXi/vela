set(TRAFFIC_ANALYSIS_SOURCES
    state_block.cpp
    traffic_parser.cpp
    performance_predictor.cpp
    allocation_synthesizer.cpp
)

set(TRAFFIC_ANALYSIS_HEADERS
    state_block.h
    traffic_digest.h
    performance_predictor.h
    allocation_synthesizer.h
    register_call.h
)

add_library(p4c-traffic-analysis ${TRAFFIC_ANALYSIS_SOURCES})

target_include_directories(p4c-traffic-analysis PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${P4C_SOURCE_DIR}
    ${P4C_BINARY_DIR}
    ${P4C_SOURCE_DIR}/frontends
    ${P4C_SOURCE_DIR}/ir
)

find_path(RAPIDJSON_INCLUDE_DIR rapidjson/document.h
    HINTS ${CMAKE_BINARY_DIR}/_deps/rapidjson/include
)

if (RAPIDJSON_INCLUDE_DIR)
    target_include_directories(p4c-traffic-analysis PRIVATE
        ${RAPIDJSON_INCLUDE_DIR}
    )
else()
    message(FATAL_ERROR "RapidJSON include directory not found.")
endif()

target_link_libraries(p4c-traffic-analysis
    ir
    frontend
    ir-generated
    backends-common
    ${P4C_LIBRARIES}
    ${P4C_LIB_DEPS}
    absl::strings
    absl::flat_hash_map
)

add_dependencies(p4c-traffic-analysis genIR)

install(FILES ${TRAFFIC_ANALYSIS_HEADERS}
    DESTINATION ${P4C_INCLUDE_DIR}/backends/traffic_analysis
) 