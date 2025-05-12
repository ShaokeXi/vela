#include "performance_predictor.h"

#include <cstdio>
#include <iostream>
#include <array>
#include <stdexcept>
#include <vector>
#include <numeric>
#include <algorithm>

#include "backends/traffic_analysis/state_block.h"
#include "frontends/p4/externInstance.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace P4 {

PythonPerformancePredictor::PythonPerformancePredictor(const std::string& script_path, const std::string& model_json_path)
    : script_path_(script_path), model_json_path_(model_json_path) {
    if (script_path_.empty()) {
        throw std::runtime_error("PythonPerformancePredictor: Python script path cannot be empty.");
    }
    // File existence checks for script_path_ and model_json_path_ could be added here.
    // For now, errors will be caught during script execution or when Python tries to load the model.
}

std::string PythonPerformancePredictor::serializeDescription(const PyOperationDescription& description) {
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

    for (const auto& op_pair : description) { // e.g., op_pair.first = "irb"
        rapidjson::Value op_value(rapidjson::kObjectType);
        for (const auto& bw_pair : op_pair.second) { // e.g., bw_pair.first = 4 (for b4)
            std::string bw_key_str = "b" + std::to_string(bw_pair.first);
            rapidjson::Value bw_key(bw_key_str.c_str(), allocator);
            rapidjson::Value details_array(rapidjson::kArrayType);
            for (const auto& detail : bw_pair.second) {
                rapidjson::Value detail_tuple(rapidjson::kArrayType);
                detail_tuple.PushBack(detail.count, allocator);
                detail_tuple.PushBack(detail.vrgn, allocator);
                details_array.PushBack(detail_tuple, allocator);
            }
            op_value.AddMember(bw_key, details_array, allocator);
        }
        rapidjson::Value op_key(op_pair.first.c_str(), allocator);
        doc.AddMember(op_key, op_value, allocator);
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

std::string PythonPerformancePredictor::executeScript(const std::string& command) {
    std::array<char, 256> buffer_array;
    std::string result;

    // std::cout << "PythonPerformancePredictor executing command: " << command << std::endl;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("PythonPerformancePredictor: popen() failed for command: " + command);
    }
    try {
        while (fgets(buffer_array.data(), buffer_array.size(), pipe) != nullptr) {
            result += buffer_array.data();
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    int return_code = pclose(pipe);

    if (return_code != 0) {
        throw std::runtime_error("PythonPerformancePredictor: Python script execution failed (exit code " +
                                 std::to_string(return_code) +
                                 "). Command: " + command +
                                 ". Check script's stderr for details. Script output so far: " + result);
    }
     if (result.empty()) {
         throw std::runtime_error("PythonPerformancePredictor: Python script produced no output. Command: " + command);
    }
    return result;
}

double PythonPerformancePredictor::predictThroughput(const PyOperationDescription& description) {
    std::string json_desc_str;
    try {
        json_desc_str = serializeDescription(description);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("PythonPerformancePredictor: Failed to serialize operation description to JSON: ") + e.what());
    }

    std::string command = "python3 \"" + script_path_ + "\" --desc '" + json_desc_str + "' --model_file \"" + model_json_path_ + "\"";

    std::string script_output;
    try {
        script_output = executeScript(command);
    } catch (const std::exception& e) {
        throw;
    }

    try {
        if (!script_output.empty() && script_output.back() == '\n') {
            script_output.pop_back();
        }
        return std::stod(script_output);
    } catch (const std::invalid_argument& ia) {
        throw std::runtime_error("PythonPerformancePredictor: Invalid argument. Cannot parse script output to double. Output: '" +
                                 script_output + "'. Error: " + ia.what());
    } catch (const std::out_of_range& oor) {
        throw std::runtime_error("PythonPerformancePredictor: Out of range. Script output is too large for double. Output: '" +
                                 script_output + "'. Error: " + oor.what());
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("PythonPerformancePredictor: An unexpected error occurred parsing script output: ") +
                                 e.what() + ". Output: '" + script_output + "'");
    }
}

static void addToOpsMapLocal(P4::PyBitwidthMap& ops_map, int width_bytes, int vrgn) {
    auto& details_list = ops_map[width_bytes];
    auto it = std::find_if(details_list.begin(), details_list.end(),
                           [&](const P4::PyOperationDetails& d) { return d.vrgn == vrgn; });
    if (it != details_list.end()) {
        it->count++;
    } else {
        details_list.emplace_back(1, vrgn);
    }
}

PyOperationDescription PerformancePredictorLogic::buildOperationDescriptionForBlocks(
    const std::vector<const P4::StateBlock*>& blocks
) {
    PyOperationDescription desc;
    PyBitwidthMap read_ops_by_width;
    PyBitwidthMap write_ops_by_width;

    for (const P4::StateBlock* block : blocks) {
        if (!block) continue;
        for (const IR::Declaration_Instance* p4_decl_inst : block->registers) {
            if (!p4_decl_inst) continue;
            const IR::Type* instance_type = p4_decl_inst->type;
            const IR::Vector<IR::Type>* type_args = nullptr;
            if (auto spec_type = instance_type->to<IR::Type_Specialized>()) {
                type_args = spec_type->arguments;
            } else {
                continue;
            }
            if (!type_args || type_args->empty()) {
                continue;
            }
            const IR::Type* reg_element_type = type_args->at(0);
            if (!reg_element_type) {
                continue;
            }
            int bitwidth = reg_element_type->width_bits();
            if (bitwidth <= 0) {
                continue;
            }
            int width_bytes = (bitwidth + 7) / 8;
            unsigned size_val = 1;
            if (p4_decl_inst->arguments && !p4_decl_inst->arguments->empty()) {
                const IR::Argument* size_arg = p4_decl_inst->arguments->at(0);
                if (auto cst = size_arg->expression->to<IR::Constant>()) {
                    size_val = cst->asUnsigned();
                }
            }
            if (size_val == 0) size_val = 1;
            int vrgn = static_cast<int>(size_val);
            addToOpsMapLocal(read_ops_by_width, width_bytes, vrgn);
            addToOpsMapLocal(write_ops_by_width, width_bytes, vrgn);
        }
    }

    char memory_char = 'i';
    char access_char = 'a';
    std::string final_read_key; final_read_key += memory_char; final_read_key += 'r'; final_read_key += access_char;
    std::string final_write_key; final_write_key += memory_char; final_write_key += 'w'; final_write_key += access_char;

    if (!read_ops_by_width.empty()) { desc[final_read_key] = read_ops_by_width; }
    if (!write_ops_by_width.empty()) { desc[final_write_key] = write_ops_by_width; }
    return desc;
}

double PerformancePredictorLogic::getMaxUnitThroughput(const P4::StateBlock* block, Location desired_location) {
    (void)desired_location;
    if (!block) return 0.0;
    std::vector<const P4::StateBlock*> current_block_vec = {block};
    PyOperationDescription block_op_desc = buildOperationDescriptionForBlocks(current_block_vec);
    if (block_op_desc.empty()) {
        return 1e9; 
    }
    return python_predictor_ref_.predictThroughput(block_op_desc);
}

bool PerformancePredictorLogic::checkPerformance(
    const AllocationPlan& plan,
    double target_throughput_mpps,
    const std::vector<const P4::StateBlock*>& all_blocks
) {
    std::vector<const P4::StateBlock*> nic_allocated_blocks;
    for (const auto* b : all_blocks) {
        auto it = plan.find(b);
        if (it != plan.end() && (it->second == Location::NIC_IMEM || it->second == Location::NIC_EMEM)) {
            nic_allocated_blocks.push_back(b);
        }
    }
    if (nic_allocated_blocks.empty()) {
        return target_throughput_mpps == 0.0;
    }
    PyOperationDescription nic_op_desc = buildOperationDescriptionForBlocks(nic_allocated_blocks);
    if (nic_op_desc.empty()) {
        return target_throughput_mpps == 0.0; 
    }
    double predicted_nic_throughput = python_predictor_ref_.predictThroughput(nic_op_desc);
    return predicted_nic_throughput >= target_throughput_mpps;
}

bool PerformancePredictorLogic::checkResources(
    const AllocationPlan& plan,
    const std::vector<const P4::StateBlock*>& all_blocks,
    unsigned long imem_limit_bytes_override,
    unsigned long emem_limit_bytes_override,
    double pcie_limit_gbps,
    double host_traffic_mpps,
    int avg_pkt_size_kb
) {
    unsigned long actual_imem_limit = (imem_limit_bytes_override == 0) ? DEFAULT_IMEM_LIMIT_BYTES : imem_limit_bytes_override;
    // unsigned long actual_emem_limit = (emem_limit_bytes_override == 0) ? DEFAULT_EMEM_LIMIT_BYTES : emem_limit_bytes_override;

    unsigned long imem_consumed_bytes = 0;
    // unsigned long emem_consumed_bytes = 0;

    for (const auto* b : all_blocks) {
        auto plan_it = plan.find(b);
        Location loc = (plan_it == plan.end()) ? Location::HOST_CPU : plan_it->second;
        if (loc == Location::NIC_IMEM || loc == Location::NIC_EMEM) {
            unsigned long block_memory = 0;
            for (const IR::Declaration_Instance* p4_decl_inst : b->registers) {
                if (!p4_decl_inst) continue;
                const IR::Type* instance_type = p4_decl_inst->type;
                const IR::Vector<IR::Type>* type_args = nullptr;
                if (auto spec_type = instance_type->to<IR::Type_Specialized>()) { type_args = spec_type->arguments; }
                if (!type_args || type_args->empty()) continue;
                const IR::Type* reg_element_type = type_args->at(0);
                if (!reg_element_type) continue;
                int bitwidth = reg_element_type->width_bits();
                if (bitwidth <= 0) continue;
                int width_bytes = (bitwidth + 7) / 8;
                unsigned size_val = 1;
                if (p4_decl_inst->arguments && !p4_decl_inst->arguments->empty()) {
                    const IR::Argument* size_arg = p4_decl_inst->arguments->at(0);
                    if (auto cst = size_arg->expression->to<IR::Constant>()) { size_val = cst->asUnsigned(); }
                }
                if (size_val == 0) size_val = 1;
                block_memory += static_cast<unsigned long>(width_bytes) * size_val;
            }
            if (loc == Location::NIC_IMEM) {
                imem_consumed_bytes += block_memory;
            }
        }
    }
    if (imem_consumed_bytes > actual_imem_limit) {
        std::cout << "  Resource Check: IMEM FAIL - Consumed: " << imem_consumed_bytes << " > Limit: " << actual_imem_limit << std::endl;
        return false;
    }
     std::cout << "  Resource Check: IMEM PASS - Consumed: " << imem_consumed_bytes << " <= Limit: " << actual_imem_limit << std::endl;

    if (host_traffic_mpps > 0) {
        double pcie_bw_consumed_gbps = host_traffic_mpps * avg_pkt_size_kb * 8.0;
        if (pcie_bw_consumed_gbps > pcie_limit_gbps) {
            std::cout << "  Resource Check: PCIe FAIL - Consumed: " << pcie_bw_consumed_gbps << " Gbps > Limit: " << pcie_limit_gbps << " Gbps" << std::endl;
            return false;
        }
        std::cout << "  Resource Check: PCIe PASS - Consumed: " << pcie_bw_consumed_gbps << " Gbps <= Limit: " << pcie_limit_gbps << " Gbps" << std::endl;
    }
    return true;
}

} // namespace P4
