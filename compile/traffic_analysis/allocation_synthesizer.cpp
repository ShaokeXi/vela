#include "allocation_synthesizer.h"
#include "performance_predictor.h"
#include "state_block.h"
#include "frontends/p4/externInstance.h"
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace P4 {

AllocationSynthesizer::AllocationSynthesizer(
    StateBlockAnalyzer& analyzer,
    PerformancePredictorLogic& perf_predictor,
    const std::vector<const P4::StateBlock*>& all_blocks,
    const std::map<const P4::StateBlock*, uint64_t>& access_counts,
    double target_throughput
) : analyzer_ref_(analyzer),
    perf_predictor_ref_(perf_predictor),
    all_p4_blocks_(all_blocks),
    block_access_counts_(access_counts),
    target_throughput_mpps_(target_throughput) {
    initializeUnits();
}

double AllocationSynthesizer::estimateInstructionCost(const P4::StateBlock* block) {
    // Instruction cost (Is) can be estimated as the total number of read/write operations
    // associated with the registers in this block, as per actionRegisterUsage.
    // This is a simplification. A more complex model could weigh different ops differently.
    double cost = 0.0;
    PyOperationDescription op_desc = perf_predictor_ref_.buildOperationDescriptionForBlocks({block});

    for (const auto& op_type_pair : op_desc) { // e.g., op_type_pair.first is "ira" or "iwa"
        for (const auto& bw_pair : op_type_pair.second) { // e.g., bw_pair.first is bitwidth
            for (const auto& details : bw_pair.second) { // PyOperationDetails: count, vrgn
                cost += details.count;
            }
        }
    }
    return cost == 0.0 ? 1.0 : cost; // Avoid division by zero later if a block has no ops
}

double AllocationSynthesizer::estimateRegisterElementsN(const P4::StateBlock* block) {
    // Ns: Sum of effective sizes (VRGNs) of registers in the block
    double n_elements = 0.0;
    if (!block) return 1.0; // Should not happen if block is valid

    for (const IR::Declaration_Instance* p4_decl_inst : block->registers) {
        if (!p4_decl_inst) continue;
        unsigned size_val = 1;
        if (p4_decl_inst->arguments && !p4_decl_inst->arguments->empty()) {
            const IR::Argument* size_arg = p4_decl_inst->arguments->at(0);
            if (auto cst = size_arg->expression->to<IR::Constant>()) {
                size_val = cst->asUnsigned();
            }
        }
        if (size_val == 0) size_val = 1; // Treat 0 as 1 for Ns calculation consistency
        n_elements += size_val;
    }
    return n_elements == 0.0 ? 1.0 : n_elements; // Avoid division by zero for sorting key
}

void AllocationSynthesizer::initializeUnits() {
    synthesis_units_.clear();
    for (const auto* block : all_p4_blocks_) {
        if (!block) continue;

        double access_volume_vs = 1.0; // Placeholder for V_s (access volume/frequency)
        auto ac_it = block_access_counts_.find(block);
        if (ac_it != block_access_counts_.end() && ac_it->second > 0) {
            access_volume_vs = static_cast<double>(ac_it->second);
        } else {
            // If no specific access count, keep it as a small default or 1.0
            // This makes blocks with no specific traffic still get a non-zero Vs
            // for sorting, might need adjustment based on desired behavior for "cold" blocks.
            access_volume_vs = 1.0; 
        }

        double instruction_cost_is = estimateInstructionCost(block);
        double elements_ns = estimateRegisterElementsN(block);
        
        double sorting_key_k = 0.0;
        if (elements_ns > 0) { // Ensure Ns is not zero to prevent division by zero
            sorting_key_k = (access_volume_vs * instruction_cost_is) / elements_ns;
        }

        // Estimate max throughput if placed in IMEM for filtering potentially non-offloadable units
        double imem_throughput = perf_predictor_ref_.getMaxUnitThroughput(block, Location::NIC_IMEM);
        if (imem_throughput > 0.0) { // Only consider units that have some processing capability on NIC
            synthesis_units_.emplace_back(block, access_volume_vs, instruction_cost_is, elements_ns, sorting_key_k, imem_throughput);
        }
    }

    // Sort units by key k in descending order (higher k is better for offloading)
    std::sort(synthesis_units_.begin(), synthesis_units_.end(), [](const SynthesisUnit& a, const SynthesisUnit& b) {
        return a.sorting_key_k > b.sorting_key_k;
    });
}

AllocationPlan AllocationSynthesizer::run() {
    AllocationPlan current_plan;
    // Initialize all blocks to HOST_CPU
    for (const auto* block : all_p4_blocks_) {
        current_plan[block] = Location::HOST_CPU;
    }

    std::cout << "\n--- Starting Allocation Synthesis ---" << std::endl;
    std::cout << "Target throughput for synthesis: " << target_throughput_mpps_ << " Mpps" << std::endl;
    std::cout << "Total P4 blocks: " << all_p4_blocks_.size() << std::endl;
    std::cout << "Number of synthesizable units (after filtering): " << synthesis_units_.size() << std::endl;

    for (const auto& unit : synthesis_units_) {
        std::string block_display_name = "N/A";
        if (unit.block) {
            if (!unit.block->registers.empty()){
                std::stringstream temp_ss;
                bool first = true;
                for(const auto* reg : unit.block->registers) {
                    if(!first) temp_ss << ", ";
                    temp_ss << reg->getName().toString();
                    first = false;
                }
                block_display_name = temp_ss.str();
            } else {
                 block_display_name = "Unnamed_Empty_Block";
            }
        }

        std::cout << "  Considering unit (Block: " << block_display_name 
                  << ", Vs: " << unit.access_volume_Vs 
                  << ", Is: " << unit.instruction_cost_Is 
                  << ", Ns: " << unit.elements_Ns 
                  << ", Key k: " << unit.sorting_key_k 
                  << ", IMEM TP: " << unit.imem_max_throughput << " Mpps)" << std::endl;

        // Try to place on NIC_IMEM first
        AllocationPlan temp_plan = current_plan;
        temp_plan[unit.block] = Location::NIC_IMEM;

        std::cout << "    Attempting to place on NIC_IMEM..." << std::endl;
        bool can_place_imem = perf_predictor_ref_.checkPerformance(temp_plan, target_throughput_mpps_, all_p4_blocks_)
                           && perf_predictor_ref_.checkResources(temp_plan, all_p4_blocks_); 
                           // Using default resource limits in checkResources, can pass specific if needed

        if (can_place_imem) {
            std::cout << "      SUCCESS: Placed on NIC_IMEM. Performance and resource checks passed." << std::endl;
            current_plan = temp_plan;
        } else {
            std::cout << "      FAILURE: Could not place on NIC_IMEM (performance/resource constraints not met). Keeping on HOST_CPU." << std::endl;
            // TODO: Try NIC_EMEM if it's a distinct option with different characteristics/limits
            // For now, if NIC_IMEM fails, it remains on HOST_CPU as per current_plan default
        }
    }
    std::cout << "--- Allocation Synthesis Complete ---" << std::endl;
    return current_plan;
}

std::string AllocationSynthesizer::locationToString(Location loc) {
    switch (loc) {
        case Location::HOST_CPU: return "HOST_CPU";
        case Location::NIC_IMEM: return "NIC_IMEM";
        case Location::NIC_EMEM: return "NIC_EMEM";
        default: return "Unknown";
    }
}

void AllocationSynthesizer::dumpPlan(const AllocationPlan& plan, std::ostream& out) const {
    out << "\n--- Final Allocation Plan ---" << std::endl;
    out << std::left << std::setw(45) << "State Block" // Increased width for potentially longer names
        << std::setw(15) << "Allocated To" << std::endl;
    out << std::string(60, '-') << std::endl;

    for (const auto* p4_block : all_p4_blocks_) {
        std::string block_name_str = "Unknown Block";
        if (p4_block) {
            if (!p4_block->registers.empty()) {
                 std::stringstream ss_reg_names;
                 bool first_reg = true;
                 for(const auto* reg : p4_block->registers) {
                    if(!first_reg) ss_reg_names << ", ";
                    ss_reg_names << reg->getName().toString();
                    first_reg = false;
                 }
                 block_name_str = ss_reg_names.str();
                 // Ensure a non-empty string if registers somehow yield an empty name string
                 if(block_name_str.empty() && !p4_block->registers.empty()) {
                    block_name_str = "Block_with_unnamed_registers"; 
                 }
            } else {
                block_name_str = "Unnamed_Empty_Block";
            }
        }
        
        auto it = plan.find(p4_block);
        Location loc = (it != plan.end()) ? it->second : Location::HOST_CPU; // Default to HOST if not in plan (should not happen for all_p4_blocks_)
        
        out << std::left << std::setw(45) << block_name_str
            << std::setw(15) << locationToString(loc) << std::endl;
    }
}

void AllocationSynthesizer::dumpSynthesisUnits(std::ostream& out) const {
    out << "\n--- Sorted Synthesis Units (Order of Consideration) ---" << std::endl;
    out << std::left 
        << std::setw(45) << "State Block" 
        << std::setw(15) << "AccessVol(Vs)"
        << std::setw(15) << "InstrCost(Is)"
        << std::setw(15) << "Elements(Ns)"
        << std::setw(15) << "SortKey(k)"
        << std::setw(20) << "Est.IMEM TP(Mpps)" << std::endl;
    out << std::string(125, '-') << std::endl;

    for (const auto& unit : synthesis_units_) {
        std::string block_name_str = "Unknown Block";
        if (unit.block) {
            if (!unit.block->registers.empty()) {
                 std::stringstream ss_reg_names;
                 bool first_reg = true;
                 for(const auto* reg : unit.block->registers) {
                    if(!first_reg) ss_reg_names << ", ";
                    ss_reg_names << reg->getName().toString();
                    first_reg = false;
                 }
                 block_name_str = ss_reg_names.str();
                 if(block_name_str.empty() && !unit.block->registers.empty()) {
                    block_name_str = "Block_with_unnamed_registers"; 
                 }
            } else {
                block_name_str = "Unnamed_Empty_Block";
            }
        }
        out << std::left 
            << std::setw(45) << block_name_str
            << std::setw(15) << std::fixed << std::setprecision(2) << unit.access_volume_Vs
            << std::setw(15) << std::fixed << std::setprecision(2) << unit.instruction_cost_Is
            << std::setw(15) << std::fixed << std::setprecision(2) << unit.elements_Ns
            << std::setw(15) << std::fixed << std::setprecision(5) << unit.sorting_key_k
            << std::setw(20) << std::fixed << std::setprecision(2) << unit.imem_max_throughput
            << std::endl;
    }
}

} // namespace P4
