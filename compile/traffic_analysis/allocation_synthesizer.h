#ifndef P4C_ALLOCATION_SYNTHESIZER_H
#define P4C_ALLOCATION_SYNTHESIZER_H

#include "ir/ir.h"
#include "backends/traffic_analysis/state_block.h"
#include <vector>
#include <map>
#include <string>
#include <cstdint>

namespace P4 {

class PerformancePredictorLogic;
class StateBlockAnalyzer;

// Location Enum: Defines where a state block can be allocated
enum class Location {
    HOST_CPU,
    NIC_IMEM, // Internal Memory on NIC
    NIC_EMEM  // External Memory on NIC
};

// Allocation Plan: Maps each state block to a location
using AllocationPlan = std::map<const P4::StateBlock*, Location>;

// Synthesis Unit: Represents a state block with its characteristics for allocation decisions
struct SynthesisUnit {
    const P4::StateBlock* block = nullptr;
    double access_volume_Vs = 0.0;      // Access volume (e.g., from traffic analysis - packets/sec or total accesses)
    double instruction_cost_Is = 0.0;   // Estimated instruction cost for processing related to this block
    double elements_Ns = 0.0;           // Sum of effective sizes (VRGNs) of registers in the block
    double sorting_key_k = 0.0;         // Key for sorting units: (Vs * Is) / Ns
    // Store max throughput if offloaded to quickly check without re-predicting during filtering
    double imem_max_throughput = 0.0; 
    // double emem_max_throughput = 0.0;

    // Default constructor
    SynthesisUnit() = default;

    // Parameterized constructor
    SynthesisUnit(const P4::StateBlock* b, double v, double i, double n, double k_val, double imem_tp)
        : block(b), access_volume_Vs(v), instruction_cost_Is(i), elements_Ns(n), sorting_key_k(k_val), imem_max_throughput(imem_tp) {}
};

class AllocationSynthesizer {
private:
    StateBlockAnalyzer& analyzer_ref_;
    PerformancePredictorLogic& perf_predictor_ref_;
    std::vector<const P4::StateBlock*> all_p4_blocks_;
    std::map<const P4::StateBlock*, uint64_t> block_access_counts_;
    double target_throughput_mpps_;

    std::vector<SynthesisUnit> synthesis_units_;

    void initializeUnits();
    double estimateInstructionCost(const P4::StateBlock* block);
    double estimateRegisterElementsN(const P4::StateBlock* block);

public:
    AllocationSynthesizer(
        StateBlockAnalyzer& analyzer,
        PerformancePredictorLogic& perf_predictor,
        const std::vector<const P4::StateBlock*>& all_blocks, 
        const std::map<const P4::StateBlock*, uint64_t>& access_counts,
        double target_throughput
    );

    AllocationPlan run();
    void dumpPlan(const AllocationPlan& plan, std::ostream& out = std::cout) const;
    static std::string locationToString(Location loc);
    void dumpSynthesisUnits(std::ostream& out = std::cout) const;

};

} // namespace P4

#endif // P4C_ALLOCATION_SYNTHESIZER_H 