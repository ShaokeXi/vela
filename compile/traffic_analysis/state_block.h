#ifndef P4C_STATE_BLOCK_H
#define P4C_STATE_BLOCK_H

#include "ir/ir.h"
#include "ir/visitor.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <iostream>

#include "backends/traffic_analysis/traffic_digest.h"

namespace P4 {

class StateBlock {
public:
    std::set<const IR::Declaration_Instance*> registers;
    std::vector<StateBlock*> dependencies;
    cstring associatedFlowGroup;
    std::set<cstring> flowGroups;  // Set of flow groups associated with this state block

    StateBlock() = default;
    void addRegister(const IR::Declaration_Instance* reg) { registers.insert(reg); }
    void addDependency(StateBlock* dep) { dependencies.push_back(dep); }
    void setFlowGroup(cstring flowGroup) { associatedFlowGroup = flowGroup; }
};

class StateBlockAnalyzer : public Inspector {
    ReferenceMap* refMap;
    TypeMap* typeMap;
    const IR::P4Program* program;  // The P4 program being analyzed
    std::map<const IR::Declaration_Instance*, StateBlock*> registerToBlock;
    std::vector<StateBlock*> stateBlocks;

    // Context for dependency analysis within an action
    const IR::P4Action* currentAction = nullptr;
    std::set<const IR::Declaration_Instance*> readsInCurrentAction;
    std::set<const IR::Declaration_Instance*> writesInCurrentAction;

    std::map<const IR::P4Action*,
             std::pair<std::set<const IR::Declaration_Instance*>, // Reads
                       std::set<const IR::Declaration_Instance*>>> // Writes
        actionRegisterUsage;

public:
    StateBlockAnalyzer(ReferenceMap* refMap, TypeMap* typeMap, const IR::P4Program* program)
        : refMap(refMap), typeMap(typeMap), program(program) {
        CHECK_NULL(refMap);
        CHECK_NULL(typeMap);
        CHECK_NULL(program);
        setName("StateBlockAnalyzer");
    }

    // Accessors for refMap and typeMap
    P4::ReferenceMap* getRefMap() const { return refMap; }
    P4::TypeMap* getTypeMap() const { return typeMap; }

    void analyze();
    void analyzeRegisterDependencies();
    void identifyStateBlocks();
    void mapFlowGroups();

    // Visitor methods
    bool preorder(const IR::Node* node) override;
    bool preorder(const IR::Declaration_Instance* decl) override;
    bool preorder(const IR::MethodCallStatement* methodCall) override;
    bool preorder(const IR::MethodCallExpression* mce) override;
    bool preorder(const IR::P4Table* table) override;
    bool preorder(const IR::P4Control* control) override;
    bool preorder(const IR::P4Action* action) override;
    bool preorder(const IR::AssignmentStatement* assign) override;
    bool preorder(const IR::IfStatement* ifStmt) override;

    // Utility methods
    const std::vector<StateBlock*>& getStateBlocks() const { return stateBlocks; }
    void generateDependencyGraph(const char* outFile) const;
    void dumpAnalysis() const;

    // Traffic Analysis Phase
    void calculateAndDumpFrequencies(const std::vector<TrafficRecord>& traffic,
                                     const ControlPlaneRules& rules);

private:
    // Helper methods
    void addRegisterDependency(const IR::Declaration_Instance* reg1, const IR::Declaration_Instance* reg2);
    StateBlock* getOrCreateStateBlock(const IR::Declaration_Instance* inst);
    void mergeStateBlocks(StateBlock* block1, StateBlock* block2);
    std::set<const IR::Declaration_Instance*> findRegisterReads(const IR::Expression* expr);
    // Declarations for the representative block helpers
    StateBlock* getRepresentativeBlock(const IR::Declaration_Instance* inst) const;
    StateBlock* getRepresentativeBlock(const StateBlock* block) const;
};

// Function to check memory requirements
bool checkMemoryRequirements(const std::vector<const StateBlock*>& blocksToAllocate, unsigned long availableMemoryBytes);

}  // namespace P4

#endif  // P4C_STATE_BLOCK_H 