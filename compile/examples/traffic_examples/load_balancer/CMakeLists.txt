# Add the executable
add_executable(analyze_load_balancer
    analyze_load_balancer.cpp
)

# Add dependency on genIR
add_dependencies(analyze_load_balancer genIR)

# Add dependency on parser generation target
add_dependencies(analyze_load_balancer frontend-parser-gen)

# Explicitly depend on the analysis library target
add_dependencies(analyze_load_balancer p4c-traffic-analysis)

# Include directories
target_include_directories(analyze_load_balancer PUBLIC
    ${P4C_SOURCE_DIR}
    ${P4C_BINARY_DIR}
    ${abseil_SOURCE_DIR}
    ${abseil_BINARY_DIR}
)

# Link libraries
target_link_libraries(analyze_load_balancer
    ${P4C_CORE_LIBRARIES}
    p4c-traffic-analysis
    frontend
    ir
    absl::strings
    absl::flat_hash_map
    absl::flat_hash_set
)

# Create a symbolic link to the P4 program
add_custom_command(
    TARGET analyze_load_balancer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink
            ${CMAKE_CURRENT_SOURCE_DIR}/load_balancer.p4
            ${CMAKE_CURRENT_BINARY_DIR}/load_balancer.p4
)

# Add test - updated to pass the P4 file as an argument
add_test(NAME test_load_balancer_analysis
         COMMAND analyze_load_balancer load_balancer.p4
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})