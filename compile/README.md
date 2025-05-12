# Traffic-Aware Code Analysis Framework for SmartNICs

## Overview
This framework analyzes P4 programs to guide efficient code generation for multi-threaded SmartNICs by:
1. Analyzing stateful operations and their dependencies
2. Correlating traffic patterns with execution frequencies
3. Optimizing resource allocation based on performance predictions

## Integration Flow

The analysis process involves several stages, utilizing components from the P4 compiler (p4c) and custom analysis modules:

```
P4 Program (e.g., load_balancer.p4)
    ↓
P4C Frontend (parsing, type checking using p4c libraries)
    ↓
StateBlockAnalyzer (backends/traffic_analysis/state_block.cpp)
    - Identifies register dependencies from P4 IR
    - Groups registers into state blocks using SCC (Strongly Connected Components)
    - Maps tables (flow groups) to relevant state blocks
    - Outputs dependency graph (e.g., load_balancer.dot)
    ↓
Traffic Pattern Correlation (backends/traffic_analysis/traffic_parser.cpp)
    - Parses traffic trace (e.g., traffic_sample.txt)
    - Parses control plane rules (e.g., connTbl_rules.txt)
    - Calculates access frequencies for each state block
    ↓
Resource Allocation Synthesis (backends/traffic_analysis/allocation_synthesizer.cpp)
    - Uses Performance Predictor (backends/traffic_analysis/performance_predictor.cpp)
    - Evaluates NIC (IMEM/EMEM) vs. Host placement for state blocks
    - Generates an allocation plan to meet performance targets
    ↓
Final Output
    - State dependency graph (.dot file)
    - Log file (out.log) with analysis details:
        - Identified state blocks and their registers
        - Inter-block dependencies
        - Flow group mappings
        - Access frequencies per block
        - Synthesized allocation plan and performance predictions
```

## Implementation

### 1. State Block Analysis
**Goal:** Group stateful P4 elements (primarily registers) into "state blocks" based on cyclic Read-after-Write (RaW) dependencies. This ensures that elements whose states influence each other within a feedback loop are grouped together.

**Core Logic (`P4::StateBlockAnalyzer` in `backends/traffic_analysis/state_block.cpp`):**

1.  **Intra-Action Dependency Tracking (Visitor methods like `preorder(const IR::MethodCallStatement*)`):**
    *   Tracks register reads (`readsInCurrentAction`) and writes (`writesInCurrentAction`) within the scope of each `P4Action`.
    *   For a register write, dependencies are added from *all* registers previously read in the action (`readsInCurrentAction`) to the written register. This captures dependencies mediated by local variables.
    *   Dependencies from reads within `if` statement conditions are added to writes within the corresponding branches (`preorder(const IR::IfStatement*)`).
2.  **Storing Action Usage (`preorder(const IR::P4Action*)`):**
    *   After visiting an action body, the identified register reads and writes for that action are stored in the `actionRegisterUsage` map (member of `StateBlockAnalyzer`).
3.  **Identifying State Blocks (`identifyStateBlocks()`):**
    *   Builds an initial dependency graph where nodes are individual registers.
    *   Runs Tarjan's algorithm to find Strongly Connected Components (SCCs) in this graph.
    *   Creates final `StateBlock` objects, merging all registers from the initial blocks within each SCC.
    *   Recomputes dependencies between these final merged blocks.
4.  **Mapping Flow Groups (`mapFlowGroups()` using `TableFinder` helper class):**
    *   Iterates through P4 tables found in the program.
    *   For each action associated with a table, retrieves the stored register usage from `actionRegisterUsage`.
    *   Maps the table name (treated as a flow group identifier) to the final `StateBlock`(s) containing the registers used by its actions.

**Example Output (`load_balancer.p4`):**
*   **State Blocks:**
    *   Block 0: `{MinLoad_0, MinDip_0}` (due to cyclic dependency)
    *   Block 1: `{DipCntr_0}` (due to self-dependency)
*   **Dependencies:** `Block 1 -> Block 0`
*   **Flow Groups:** `connTbl_0` mapped to both Block 0 and Block 1.
*   A DOT file (`load_balancer.dot`) is generated visualizing these blocks and dependencies.

### 2. Traffic Pattern Analysis
**Goal:** Correlate observed traffic patterns (from a sample trace file and control plane rules) with the analyzed state blocks to determine the access frequency of each block.

**Inputs:**
1.  State block analysis results (from `StateBlockAnalyzer`).
2.  Traffic trace file (e.g., `examples/traffic_examples/load_balancer/traffic_sample.txt`): Format `timestamp pkt_len srcIP dstIP srcPort dstPort proto`.
3.  Control Plane Rules file (e.g., `examples/traffic_examples/load_balancer/connTbl_rules.txt`): Defines static table entries. For `load_balancer.p4`, this maps `srcIP` to a `dip` (index for `DipCntr`).

**Implementation (`analyze_load_balancer.cpp` with helpers):**

1.  **Traffic Trace Parser (`TrafficParser` in `backends/traffic_analysis/traffic_parser.cpp`):**
    *   Parses the traffic trace file line-by-line.
    *   Stores relevant fields (timestamp, srcIP, dstIP, etc.) into `TrafficRecord` objects.
2.  **Control Plane Rule Parser (within `TrafficParser` or dedicated functions):**
    *   Parses the control plane rule file. For `load_balancer.p4`, this means reading `src_ip_key dip_value` lines.
    *   Stores these rules in a map (e.g., `std::map<std::string, std::string>` for srcIP to DIP).
3.  **Correlate Traffic and Calculate Frequencies (in `analyze_load_balancer.cpp`):**
    *   Initializes an access counter for each final `StateBlock`.
    *   Iterates through each parsed `TrafficRecord`.
    *   **For `load_balancer.p4` example:**
        *   **Block 0 (`MinLoad`, `MinDip`):** Accessed based on `meta.vip_id`, derived from `dstIP` in the traffic record (`hdr.ipv4.dst_addr & 0x03`). The counter for the block containing `MinLoad_0`/`MinDip_0` is incremented.
        *   **Block 1 (`DipCntr`):** Accessed based on the `dip` obtained by looking up the `TrafficRecord`'s `srcIP` in the parsed `connTbl` rules. The counter for the block containing `DipCntr_0` is incremented.
    *   The final `blockAccessCounts` are stored and printed.

**Expected Output:** The console output (`out.log`) includes a summary of total access counts for each state block based on the provided traffic and rules. For `load_balancer.p4`, this shows how many times the `{MinLoad, MinDip}` block and the `{DipCntr}` block were accessed.

**Note on Generality:** The control plane rule parsing and specific correlation logic (how packet fields map to register indices) are currently tailored to the `load_balancer.p4` example. Generalizing this to arbitrary P4 programs would require a more sophisticated way to understand table key structures and action semantics, or a standardized format for control plane state.

### 3. Resource Allocation Synthesis
**Goal:** Develop a backend that synthesizes a resource allocation plan, deciding whether to place state element groups (a state block accessed by a specific flow group ID, effectively a "unit" for allocation) on different SmartNIC memory tiers (IMEM/EMEM) or the host CPU. The objective is to meet performance targets and respect resource constraints while minimizing host CPU load.

**Modules:**
1.  **Performance Predictor (`P4::PerformancePredictorLogic` in `backends/traffic_analysis/performance_predictor.cpp` wrapping `PythonPerformancePredictor`):** Estimates the achievable throughput for a given allocation plan.
2.  **Synthesis Algorithm (`P4::AllocationSynthesizer` in `backends/traffic_analysis/allocation_synthesizer.cpp`):** Uses the predictor to guide a heuristic search for an allocation plan.

**Implementation Details:**

*   **3.1 Performance Predictor Implementation (`PerformancePredictor` class):**
    *   **Hardware Parameters:** Python-based predictor (`predictor_script.py`, `model.json`) uses hardware model parameters. The C++ side prepares operation descriptions.
    *   **Operation Intensity & Throughput:** `buildOperationDescription` in `analyze_load_balancer.cpp` and `buildOperationDescriptionForBlocks` in `PerformancePredictorLogic` gather register access details (width, count) for the Python predictor.
    *   **Lock-Free Throughput Calculation:** `GetMaxUnitThroughput` estimates throughput for a state block at a given location (IMEM, EMEM, Host) using the Roofline model, considering the number of memory operations.
    *   **Lock Contention Model:** `EstimateLockedThroughput` adjusts throughput predictions if locks are inferred for accessing the state block.
    *   **Performance and Resource Checks:**
        *   `CheckPerformance`: Verifies if individual NIC-allocated units meet their required throughput (derived from traffic volume) and if the overall plan meets a global target throughput.
        *   `CheckResources`: Checks aggregate memory usage per location against defined capacities and estimates PCIe bandwidth.

*   **3.2 Synthesis Algorithm Implementation (`AllocationSynthesizer` class):**
    *   **Data Structures:** Represents state element groups (units to be allocated, typically a state block or part of it if flow-granularity is finer) and the allocation plan which maps each unit to a location (IMEM, EMEM, Host).
    *   **Input Aggregation:** Takes state blocks, flow group volumes (access frequencies from Traffic Pattern Analysis), estimated instruction costs (number of memory operations per block access), performance targets, and NIC hardware parameters.
    *   **Filtering & Sorting:** Potentially offloadable units are identified. These units are sorted by a heuristic key (e.g., \(k = (\text{AccessFrequency} \cdot \text{InstructionCost}) / \text{NumEntries}\)) to prioritize "heavy" or "critical" units.
    *   **Greedy Allocation Algorithm:**
        *   Initializes all units to be on the Host CPU.
        *   Iterates through sorted units, attempting to place them on the most performant NIC memory (IMEM first, then EMEM).
        *   Uses `PerformancePredictor::CheckPerformance` and `PerformancePredictor::CheckResources` to validate if a placement is feasible.
        *   Commits feasible placements to the plan.
    *   **Output Plan:** Produces the final allocation plan, indicating the location for each state unit.

*   **Integration in `analyze_load_balancer.cpp`:**
    *   The main application (`analyze_load_balancer.cpp`) orchestrates the three phases:
        1.  Runs `StateBlockAnalyzer`.
        2.  Parses traffic and control plane rules to get access frequencies (`blockAccessCounts`).
        3.  Passes these results to `AllocationSynthesizer` to generate and print an allocation plan.

**Example Output (`load_balancer.p4`):** The `out.log` details the synthesized plan, showing which blocks (and their constituent registers) are allocated to IMEM, EMEM, or Host, along with predicted performance and resource usage.

## Directory Structure

This section describes the key files and directories added to an existing P4C source tree for this project.

```
p4c/
├── backends/
│   └── traffic_analysis/                   # Main directory for custom analysis and synthesis logic
│       ├── CMakeLists.txt                  # Builds the p4c-traffic-analysis library
│       ├── state_block.h                   # Definition of StateBlockAnalyzer, StateBlock
│       ├── state_block.cpp                 # Implementation of StateBlockAnalyzer
│       ├── traffic_digest.h                # Structures for traffic records
│       ├── traffic_parser.cpp              # Implementation of traffic and rule parsers
│       ├── performance_predictor.h         # Definition of PerformancePredictorLogic
│       ├── performance_predictor.cpp       # Implementation of PerformancePredictorLogic
│       ├── allocation_synthesizer.h        # Definition of AllocationSynthesizer
│       ├── allocation_synthesizer.cpp      # Implementation of AllocationSynthesizer
│       ├── register_call.h                 # Helper for register call abstractions
│       └── predictor/                      # Directory for Python-based predictor components
│           ├── predictor_script.py         # Python script for performance prediction
│           └── model.json                  # JSON model for the Python predictor
├── examples/
│   ├── README.md                           # This README file (p4c/examples/README.md)
│   └── traffic_examples/
│       ├── CMakeLists.txt                  # Builds executables for examples
│       └── load_balancer/
│           ├── CMakeLists.txt              # Builds analyze_load_balancer executable
│           ├── analyze_load_balancer.cpp   # Main application for the load_balancer example
│           ├── load_balancer.p4            # Example P4 program
│           ├── traffic_sample.txt          # Sample traffic trace
│           ├── connTbl_rules.txt           # Sample control plane rules
│           └── generate_rules.py           # Python script for generating connTbl_rules.txt
└── ...                                     # Other existing p4c components
```
Note: Ensure `load_balancer.p4` is correctly located within `p4c/examples/traffic_examples/load_balancer/` for the build process described. The `predictor_script.py` and `model.json` files for the performance predictor should be placed in `p4c/backends/traffic_analysis/predictor/` and made accessible to `analyze_load_balancer.cpp` (e.g., by passing their paths as arguments or by having `analyze_load_balancer.cpp` expect them in a specific relative location).

## Building and Running the Analyzer

This guide assumes you have a working P4C (P4_16 compiler) build environment. The custom analyzer is built as a library (`p4c-traffic-analysis`) and a standalone executable (`analyze_load_balancer`) that links against P4C libraries and this custom library.

**1. Prerequisites:**
   - A compiled P4C (version supporting P4_16). Ensure that P4C libraries (like `p4c-ir`, `p4c-frontend`, `p4c-midend`, `p4c-common`) are available for linking.
   - CMake (version 3.10+ recommended).
   - A C++17 compatible compiler (e.g., g++ or clang++).

**2. Directory Placement:**
   - Place the `traffic_analysis` directory into your `p4c/backends/` directory.
   - Place the `traffic_examples` directory into your `p4c/examples/` directory.

**3. Building the `p4c-traffic-analysis` Library and `analyze_load_balancer` Executable:**

   The recommended approach is to integrate the build into the main P4C CMake structure.
   - Add `add_subdirectory(backends/traffic_analysis)` to `p4c/CMakeLists.txt`.
   - Add `add_subdirectory(examples/traffic_examples)` to `p4c/CMakeLists.txt` (or ensure `examples/CMakeLists.txt` includes `traffic_examples`).

   Then, build P4C as usual. This will also build the `p4c-traffic-analysis` library and the `analyze_load_balancer` executable.

   **`p4c/backends/traffic_analysis/CMakeLists.txt`:**
   ```cmake

   # P4C's main CMakeLists.txt should handle include directories for P4C components.
   # We only need to add our own include directory.
   target_include_directories(p4c-traffic-analysis PUBLIC
       ${CMAKE_CURRENT_SOURCE_DIR}/include
   )

   set(TRAFFIC_ANALYSIS_SOURCES
       src/state_block.cpp
       src/traffic_parser.cpp
       src/performance_predictor.cpp
       src/allocation_synthesizer.cpp
   )

   add_library(p4c-traffic-analysis STATIC ${TRAFFIC_ANALYSIS_SOURCES})

   ```

   **`p4c/examples/traffic_examples/CMakeLists.txt` (Parent for examples):**
   ```cmake
   add_subdirectory(load_balancer)
   # Add other traffic examples here if any
   ```

   **`p4c/examples/traffic_examples/load_balancer/CMakeLists.txt`:**
   ```cmake

   add_executable(analyze_load_balancer analyze_load_balancer.cpp)

   # Link against our custom library and P4C's libraries.
   target_link_libraries(analyze_load_balancer PRIVATE
       ${P4C_CORE_LIBRARIES}
       p4c-traffic-analysis
       # Commonly required P4C libraries:
       frontend
       ir
       ...
   )
   ```

**4. Running the Analyzer:**
   - After building P4C (which now includes `analyze_load_balancer`), the executable will typically be in a subdirectory of your P4C build directory (e.g., `build/examples/traffic_examples/load_balancer/`).

   - Execute `analyze_load_balancer`, pointing it to the P4 program and other required files. The path to the executable depends on your build directory structure.
     ```bash
     ./examples/traffic_examples/load_balancer/analyze_load_balancer \
         ./load_balancer.p4 \
         ./load_balancer.dot \
         ../backends/traffic_analysis/predictor/predictor.py \
         ../backends/traffic_analysis/predictor/model.json
     ```
     (Adjust the relative path to `analyze_load_balancer` based on your actual build output location.)
   - An `output/` directory will be created (if it doesn't exist) in the current directory (`examples/traffic_examples/load_balancer/`), containing `out.log` and `load_balancer.dot`.