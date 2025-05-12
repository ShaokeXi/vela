#include "ir/ir.h"
#include "frontends/common/resolveReferences/referenceMap.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/parser_options.h"
#include "frontends/p4/frontend.h"
#include "frontends/common/parseInput.h"
#include "frontends/common/applyOptionsPragmas.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/p4/typeChecking/bindVariables.h"
#include "lib/gc.h"
#include "lib/compile_context.h"
#include "backends/traffic_analysis/state_block.h"
#include "frontends/common/options.h"
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include "frontends/p4/externInstance.h"
#include "backends/traffic_analysis/performance_predictor.h"
#include "backends/traffic_analysis/allocation_synthesizer.h"
#include <algorithm>
#include <map>
#include <sstream>
#include <iomanip>

using namespace P4::IR;
using P4::parseP4File;
using P4::P4COptionPragmaParser;
using P4::ApplyOptionsPragmas;

namespace P4 {

class AnalyzerOptions : public CompilerOptions {
 public:
    AnalyzerOptions() : CompilerOptions() {
        langVersion = CompilerOptions::FrontendVersion::P4_16;
    }
    ~AnalyzerOptions() noexcept override = default;
};

using AnalyzerContext = P4CContextWithOptions<AnalyzerOptions>;

}  // namespace P4

// Helper function to add to the operations map for PyOperationDescription
void addToOpsMap(P4::PyBitwidthMap& ops_map, int width_bytes, int vrgn) {
    auto& details_list = ops_map[width_bytes];
    auto it = std::find_if(details_list.begin(), details_list.end(),
                           [&](const P4::PyOperationDetails& d) { return d.vrgn == vrgn; });
    if (it != details_list.end()) {
        it->count++;
    } else {
        details_list.emplace_back(1, vrgn);
    }
}

// Function to build PyOperationDescription from state blocks
P4::PyOperationDescription buildOperationDescription(
    const std::vector<const P4::StateBlock*>& blocks,
    P4::StateBlockAnalyzer& analyzer // Analyzer provides access to refMap and typeMap
) {
    P4::PyOperationDescription desc;
    P4::PyBitwidthMap read_ops_by_width;
    P4::PyBitwidthMap write_ops_by_width;

    for (const P4::StateBlock* block : blocks) {
        if (!block) continue;
        for (const P4::IR::Declaration_Instance* p4_decl_inst : block->registers) {
            if (!p4_decl_inst) continue;

            const P4::IR::Type* instance_type = p4_decl_inst->type;
            const P4::IR::Vector<P4::IR::Type>* type_args = nullptr;

            if (auto spec_type = instance_type->to<P4::IR::Type_Specialized>()) {
                type_args = spec_type->arguments;
            } else {
                std::cerr << "Warning: Stateful element " << p4_decl_inst->getName().toString()
                          << " is not a specialized type. Cannot determine element type for performance modeling. Skipping." << std::endl;
                continue;
            }
            
            if (!type_args || type_args->empty()) {
                std::cerr << "Warning: Could not determine type arguments for stateful element " << p4_decl_inst->getName().toString() << ". Skipping." << std::endl;
                continue;
            }
            
            const P4::IR::Type* reg_element_type = type_args->at(0);
            if (!reg_element_type) {
                 std::cerr << "Warning: Could not get element type for stateful element " << p4_decl_inst->getName().toString() << ". Skipping." << std::endl;
                continue;
            }

            int bitwidth = reg_element_type->width_bits();
            if (bitwidth <= 0) {
                std::cerr << "Warning: Invalid bitwidth (" << bitwidth << ") for stateful element " << p4_decl_inst->getName().toString() << ". Skipping." << std::endl;
                continue;
            }
            int width_bytes = (bitwidth + 7) / 8;
            
            unsigned size_val = 1; // Default to scalar
            if (p4_decl_inst->arguments && !p4_decl_inst->arguments->empty()) {
                const P4::IR::Argument* size_arg = p4_decl_inst->arguments->at(0);
                if (auto cst = size_arg->expression->to<P4::IR::Constant>()) {
                    size_val = cst->asUnsigned();
                } else {
                    std::cerr << "Warning: Register size argument for " << p4_decl_inst->getName().toString() << " is not a constant. Defaulting to size 1." << std::endl;
                }
            } else {
                 std::cerr << "Warning: No size argument found for " << p4_decl_inst->getName().toString() << ". Defaulting to size 1." << std::endl;
            }
            int vrgn = (size_val == 0) ? 1 : static_cast<int>(size_val); 

            addToOpsMap(read_ops_by_width, width_bytes, vrgn);
            addToOpsMap(write_ops_by_width, width_bytes, vrgn);
        }
    }

    // TODO: In the future, these characteristics might be determined from 'analyzer'
    // or per 'block' if the model needs finer granularity.
    // For now, these are global assumptions for all operations processed by this function.
    char memory_char = 'i';  // 'i' for internal, 'e' for external
    char access_char = 'a';  // 'a' for atomic, 'b' for bulk

    std::string final_read_key;
    final_read_key += memory_char;
    final_read_key += 'r'; // read
    final_read_key += access_char;

    std::string final_write_key;
    final_write_key += memory_char;
    final_write_key += 'w'; // write
    final_write_key += access_char;

    if (!read_ops_by_width.empty()) {
        desc[final_read_key] = read_ops_by_width;
    }
    if (!write_ops_by_width.empty()) {
        desc[final_write_key] = write_ops_by_width;
    }
    return desc;
}

int main(int argc, char* const argv[]) {
    std::cerr << "Starting analyzer..." << std::endl;
    
    // Initialize the analyzer context
    std::cerr << "Initializing analyzer context..." << std::endl;
    P4::AutoCompileContext autoContext(new P4::AnalyzerContext());
    auto& options = P4::AnalyzerContext::get().options();
    
    std::string p4_file_path;
    std::string output_dot_file = "load_balancer_analyzer_output.dot";
    std::string py_script_path = "./predictor_script.py";
    std::string model_json_path = "./model.json";
    double target_throughput_mpps = 15.0;
    int avg_pkt_size_kb = 1;
    double host_traffic_mpps = 0.0;
    double pcie_limit_gbps = 64.0; // PCIe 3.0 x8

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <p4_file_path> [output_dot_file] [python_script_path] [model_json_path] [--target-throughput <mpps>] [--avg-pkt-size-kb <kb>] [--host-traffic-mpps <mpps>] [--pcie-limit-gbps <gbps>]" << std::endl;
        return 1;
    }
    p4_file_path = argv[1];
    options.file = p4_file_path;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--target-throughput") {
            if (i + 1 < argc) { target_throughput_mpps = std::stod(argv[++i]); }
            else { std::cerr << "--target-throughput requires a value." << std::endl; return 1; }
        } else if (arg == "--avg-pkt-size-kb") {
            if (i + 1 < argc) { avg_pkt_size_kb = std::stoi(argv[++i]); }
            else { std::cerr << "--avg-pkt-size-kb requires a value." << std::endl; return 1; }
        } else if (arg == "--host-traffic-mpps") {
            if (i + 1 < argc) { host_traffic_mpps = std::stod(argv[++i]); }
            else { std::cerr << "--host-traffic-mpps requires a value." << std::endl; return 1; }
        } else if (arg == "--pcie-limit-gbps") {
            if (i + 1 < argc) { pcie_limit_gbps = std::stod(argv[++i]); }
            else { std::cerr << "--pcie-limit-gbps requires a value." << std::endl; return 1; }
        } else if (i == 2 && (arg.find("--") != 0)) {
             output_dot_file = arg;
        } else if (i == 3 && (arg.find("--") != 0)) {
             py_script_path = arg;
        } else if (i == 4 && (arg.find("--") != 0)) {
             model_json_path = arg;
        } else {
            if (i == 2 && output_dot_file == "load_balancer_analyzer_output.dot") {
                output_dot_file = arg;
            } else if (i == 3 && py_script_path == "./predictor_script.py") {
                py_script_path = arg;
            } else if (i == 4 && model_json_path == "./model.json") {
                model_json_path = arg;
            } else {
                 std::cerr << "Unknown or misplaced argument: " << arg << std::endl;
                 std::cerr << "Usage: " << argv[0] << " <p4_file_path> [output_dot_file] [python_script_path] [model_json_path] [--target-throughput <mpps>] [--avg-pkt-size-kb <kb>] [--host-traffic-mpps <mpps>] [--pcie-limit-gbps <gbps>]" << std::endl;
                 return 1;
            }
        }
    }

    std::cerr << "Setting input file..." << std::endl;
    options.file = p4_file_path;
    
    std::cerr << "Setting up include paths..." << std::endl;
    char *p4includePath = getenv("P4C_16_INCLUDE_PATH");
    if (p4includePath == nullptr) {
        std::cerr << "Using default include paths" << std::endl;
        options.preprocessor_options = std::string(" -I/mnt/data/repo/p4c/p4include -I/mnt/data/repo/p4c/p4include/bmv2");
    } else {
        std::cerr << "Using environment include path: " << p4includePath << std::endl;
        options.preprocessor_options = std::string(" -I") + p4includePath;
    }
    
    std::cerr << "Preprocessor options: " << options.preprocessor_options << std::endl;
    
    std::cerr << "Creating frontend..." << std::endl;
    P4::FrontEnd frontend;
    
    std::cerr << "Parsing P4 file..." << std::endl;
    const P4::IR::P4Program* program = P4::parseP4File(options);
    if (program == nullptr) {
        std::cerr << "Failed to parse P4 file" << std::endl;
        return 1;
    }
    if (::P4::errorCount() > 0) {
        std::cerr << "Errors encountered during parsing" << std::endl;
        return 1;
    }
    
    std::cerr << "Running frontend..." << std::endl;
    program = frontend.run(options, program, &std::cout);
    if (program == nullptr) {
        std::cerr << "Frontend run failed" << std::endl;
        return 1;
    }
    if (::P4::errorCount() > 0) {
        std::cerr << "Errors encountered during frontend run" << std::endl;
        return 1;
    }
    
    std::cerr << "Applying pragmas..." << std::endl;
    if (program != nullptr) {
        P4COptionPragmaParser optionsPragmaParser(true);
        program->apply(ApplyOptionsPragmas(optionsPragmaParser));
    }
      
    // Create analyzer and generate graph
    std::cerr << "\n=== Register Analysis ===\n" << std::endl;
    P4::ReferenceMap refMap;
    P4::TypeMap typeMap;
    
    P4::PassManager passes;
    passes.setName("TypeChecking");
    
    passes.addPasses({
        new P4::ResolveReferences(&refMap),
        new P4::TypeInference(&typeMap, false),
        new P4::TypeChecking(&refMap, &typeMap)
    });
    
    passes.setStopOnError(true);
    
    program = program->apply(passes);
    if (program == nullptr || ::P4::errorCount() > 0) {
        std::cerr << "Errors encountered during type checking" << std::endl;
        return 1;
    }
    
    P4::StateBlockAnalyzer analyzer(&refMap, &typeMap, program);
    
    analyzer.analyze(); 

    if (::P4::errorCount() > 0) {
        std::cerr << "Errors during state block analysis phase operated by analyzer.analyze()." << std::endl;
        return 1;
    }
    
    analyzer.dumpAnalysis();
    analyzer.generateDependencyGraph(output_dot_file.c_str());
    std::cout << "Generated DOT file: " << output_dot_file << std::endl;

    // Ensure critical variables are defined before Allocation Synthesis
    const auto& finalBlockPtrs = analyzer.getStateBlocks(); 
    std::vector<const P4::StateBlock*> const_finalBlockPtrs;
    for (P4::StateBlock* block_ptr : finalBlockPtrs) { 
        const_finalBlockPtrs.push_back(block_ptr);
    }

    P4::PythonPerformancePredictor python_predictor_instance(py_script_path, model_json_path);
    P4::PerformancePredictorLogic perf_logic(analyzer, python_predictor_instance);

    // --- Allocation Synthesis ---
    std::cout << "\n--- Synthesizing Allocation Plan --- " << std::endl;

    // The synthesizer will use default Vs=1.0 for units if not found in map.
    std::map<const P4::StateBlock*, uint64_t> block_access_counts; 
    // if (!const_finalBlockPtrs.empty()) block_access_counts[const_finalBlockPtrs[0]] = 100;

    P4::AllocationSynthesizer synthesizer(
        analyzer, 
        perf_logic,
        const_finalBlockPtrs, 
        block_access_counts, 
        target_throughput_mpps
    );

    synthesizer.dumpSynthesisUnits(std::cout);

    P4::AllocationPlan final_plan = synthesizer.run();
    synthesizer.dumpPlan(final_plan, std::cout);

    // --- Validation of Synthesized Allocation Plan ---
    std::cout << "\n--- Validation of Synthesized Allocation Plan ---" << std::endl;

    // Calculate overall performance of the *actual* synthesized plan
    std::vector<const P4::StateBlock*> nic_allocated_blocks;
    for (const auto& pair : final_plan) {
        if (pair.second == P4::Location::NIC_IMEM || pair.second == P4::Location::NIC_EMEM) {
            nic_allocated_blocks.push_back(pair.first);
        }
    }

    double final_plan_overall_throughput_mpps = 0.0;
    if (!nic_allocated_blocks.empty()) {
        P4::PyOperationDescription nic_op_desc = perf_logic.buildOperationDescriptionForBlocks(nic_allocated_blocks);
        if (!nic_op_desc.empty()) {
            try {
                final_plan_overall_throughput_mpps = python_predictor_instance.predictThroughput(nic_op_desc);
                std::cout << "Predicted Overall Throughput of Synthesized NIC Plan: " 
                          << std::fixed << std::setprecision(2) << final_plan_overall_throughput_mpps << " Mpps" << std::endl;
            } catch (const std::runtime_error& e) {
                std::cerr << "Error during performance prediction for the final plan: " << e.what() << std::endl;
            }
        } else {
            // This case might occur if NIC-allocated blocks have no operations (e.g. empty blocks, though unlikely here)
            std::cout << "No operations identified on NIC for the final plan, overall NIC throughput is effectively 0 Mpps." << std::endl;
        }
    } else {
        std::cout << "No blocks allocated to NIC in the final plan. Overall NIC throughput is 0 Mpps." << std::endl;
    }
    
    bool final_plan_perf_ok = perf_logic.checkPerformance(final_plan, target_throughput_mpps, const_finalBlockPtrs);
    bool final_plan_res_ok = perf_logic.checkResources(final_plan, const_finalBlockPtrs, 0, 0, pcie_limit_gbps, host_traffic_mpps, avg_pkt_size_kb);

    std::cout << "Synthesized Plan Per-Unit Performance Check: " << (final_plan_perf_ok ? "PASS" : "FAIL") << std::endl;
    std::cout << "Synthesized Plan Resource Check: " << (final_plan_res_ok ? "PASS" : "FAIL") << std::endl;

    bool overall_target_met = true; // Assume true if no NIC blocks or if prediction not available/zero
    if (!nic_allocated_blocks.empty() && final_plan_overall_throughput_mpps > 0) { // Only check if there was a meaningful prediction
        overall_target_met = (final_plan_overall_throughput_mpps >= target_throughput_mpps);
        std::cout << "Overall Synthesized NIC Plan vs Target (" << std::fixed << std::setprecision(2) << target_throughput_mpps << " Mpps): " << (overall_target_met ? "PASS" : "FAIL") << std::endl;
    } else if (!nic_allocated_blocks.empty() && final_plan_overall_throughput_mpps == 0.0) {
        // If NIC blocks exist but predicted throughput is 0
        std::cout << "Overall Synthesized NIC Plan vs Target (" << std::fixed << std::setprecision(2) << target_throughput_mpps << " Mpps): FAIL (Predicted 0 Mpps for NIC blocks)" << std::endl;
        overall_target_met = false;
    }

    if (final_plan_perf_ok && final_plan_res_ok && overall_target_met) {
        std::cout << "The synthesized allocation plan meets performance and resource targets." << std::endl;
    } else {
        std::cout << "Warning: The synthesized allocation plan does NOT meet all performance and/or resource targets." << std::endl;
    }

    return ::P4::errorCount() > 0;
} 