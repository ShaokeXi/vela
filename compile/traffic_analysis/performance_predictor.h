#ifndef BACKENDS_TRAFFIC_ANALYSIS_PERF_PREDICTOR_H_
#define BACKENDS_TRAFFIC_ANALYSIS_PERF_PREDICTOR_H_

#include <map>
#include <string>
#include <vector>
#include <stdexcept>

#include "ir/ir.h"
#include "backends/traffic_analysis/state_block.h"
#include "backends/traffic_analysis/allocation_synthesizer.h"

namespace P4 {


struct PyOperationDetails {
    int count; // Number of times this operation is performed
    int vrgn;  // Virtual region size (e.g., array size)

    PyOperationDetails(int c, int v) : count(c), vrgn(v) {}
};

// Maps a bitwidth (e.g., 4 for 32-bit, 16 for 128-bit) to a list of operations
using PyBitwidthMap = std::map<int, std::vector<PyOperationDetails>>;

// Describes all operations for Python predictor, keyed by op type string (e.g., "irb", "iwa")
using PyOperationDescription = std::map<std::string, PyBitwidthMap>;

// --- Python Script-based Performance Predictor Class ---

class PythonPerformancePredictor {
 public:
    PythonPerformancePredictor(const std::string& script_path, const std::string& model_json_path);

    // Predicts throughput in Mpps (Million packets per second)
    // Throws std::runtime_error on failure (e.g., script execution error, parsing error)
    double predictThroughput(const PyOperationDescription& description);

 private:
    std::string script_path_;
    std::string model_json_path_;

    // Serializes the PyOperationDescription to a JSON string for the Python script
    std::string serializeDescription(const PyOperationDescription& description);

    // Executes a shell command and returns its standard output.
    std::string executeScript(const std::string& command);
};

class PerformancePredictorLogic {
private:
    StateBlockAnalyzer& analyzer_ref_;
    PythonPerformancePredictor& python_predictor_ref_;
    
    const unsigned long DEFAULT_IMEM_LIMIT_BYTES = 3 * 1024 * 1024; // 3MB
    const unsigned long DEFAULT_EMEM_LIMIT_BYTES = 1UL * 1024 * 1024 * 1024; // 1GB

public:
    PerformancePredictorLogic(StateBlockAnalyzer& analyzer, PythonPerformancePredictor& py_predictor)
        : analyzer_ref_(analyzer), python_predictor_ref_(py_predictor) {}

    double getMaxUnitThroughput(const P4::StateBlock* block, Location desired_location);

    bool checkPerformance(
        const AllocationPlan& plan,
        double target_throughput_mpps,
        const std::vector<const P4::StateBlock*>& all_blocks
    );

    bool checkResources(
        const AllocationPlan& plan,
        const std::vector<const P4::StateBlock*>& all_blocks,
        unsigned long imem_limit_bytes_override = 0,
        unsigned long emem_limit_bytes_override = 0,
        double pcie_limit_gbps = 64.0,
        double host_traffic_mpps = 0.0,
        int avg_pkt_size_kb = 1
    );
    
    PyOperationDescription buildOperationDescriptionForBlocks(
        const std::vector<const P4::StateBlock*>& blocks
    );
};

} // namespace P4

#endif // BACKENDS_TRAFFIC_ANALYSIS_PERF_PREDICTOR_H_

