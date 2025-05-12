#include "backends/traffic_analysis/state_block.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "backends/traffic_analysis/register_call.h"
#include "frontends/p4/methodInstance.h"
#include "backends/traffic_analysis/traffic_digest.h"

namespace P4 {

class FindRegisterReadsVisitor : public Inspector {
    P4::ReferenceMap *refMap;
    P4::TypeMap *typeMap;
    std::set<const IR::Declaration_Instance *> &reads;

 public:
    FindRegisterReadsVisitor(P4::ReferenceMap *refMap, P4::TypeMap *typeMap,
                             std::set<const IR::Declaration_Instance *> &reads)
        : refMap(refMap), typeMap(typeMap), reads(reads) {
        setName("FindRegisterReadsVisitor");
    }

    bool preorder(const IR::MethodCallExpression *mce) override {
        if (auto regCall = RegisterCall::resolve(mce, refMap, typeMap)) {
            if (regCall->isRead()) {
                reads.insert(regCall->register_);
            }
        } else {
        }
        visit(mce->arguments);
        return false;
    }

    // Handle direct references to registers if used as variables
    bool preorder(const IR::PathExpression *pe) override {
        // std::cerr << "    Visiting PathExpression in FindRegisterReads: " << pe->path->name <<
        // std::endl;
        auto decl = refMap->getDeclaration(pe->path, true);
        if (decl && decl->is<IR::Declaration_Instance>()) {
            const auto *inst = decl->to<IR::Declaration_Instance>();
            if (inst->type->toString().startsWith("Register<")) {
                // std::cerr << "      Adding potential read for PathExpr: " << inst->name <<
                // std::endl;
                reads.insert(inst);
            }
        }
        return true;
    }

};

std::set<const IR::Declaration_Instance *> StateBlockAnalyzer::findRegisterReads(
    const IR::Expression *expr) {
    std::set<const IR::Declaration_Instance *> reads;
    if (expr) {
        FindRegisterReadsVisitor finder(refMap, typeMap, reads);
        expr->apply(finder);
    }
    return reads;
}

// --- StateBlockAnalyzer ---
void StateBlockAnalyzer::analyze() {
    std::cerr << "Running analysis passes..." << std::endl;
    program->apply(*this);  // Run main visitor passes to detect ops and build initial dependencies
    identifyStateBlocks();  // Merge blocks based on detected dependencies
    mapFlowGroups();        // Map tables to final blocks
    std::cerr << "Analysis passes complete." << std::endl;
}

bool StateBlockAnalyzer::preorder(const IR::Node *node) {
    // Default visitor action - useful for debugging traversal
    (void)node;
    return true;
}

// Detect register declarations
bool StateBlockAnalyzer::preorder(const IR::Declaration_Instance *decl) {
    // std::cerr << "Visiting Declaration_Instance: " << decl->name << std::endl;
    //  Check if it's a register instantiation
    if (decl->type->is<IR::Type_Specialized>()) {
        auto specializedType = decl->type->to<IR::Type_Specialized>();
        if (specializedType->baseType->is<IR::Type_Name>()) {
            auto baseTypeName = specializedType->baseType->to<IR::Type_Name>()->path->name;
            if (baseTypeName.name == "Register") {
                std::cerr << "Found register instance: " << decl->name.name << std::endl;
                getOrCreateStateBlock(decl);  // Ensure a block exists even if unused
            }
        }
    } else if (decl->type->toString().startsWith("Register<")) {
        std::cerr << "Found register instance (heuristic): " << decl->name.name << std::endl;
        getOrCreateStateBlock(decl);
    }
    return false;  // Don't traverse inside the declaration instance itself
}

// Handle method calls within statements (e.g., reg.write(...))
bool StateBlockAnalyzer::preorder(const IR::MethodCallStatement *mcs) {
    if (!currentAction) {
        return true;
    }

    if (auto regCall = RegisterCall::resolve(mcs->methodCall, refMap, typeMap)) {
        // std::cerr << "  Found register operation (Statement) on: " <<
        // regCall->register_->name.name << std::endl;
        auto *currentReg = regCall->register_;
        getOrCreateStateBlock(currentReg);  // Ensure block exists

        if (regCall->isWrite()) {
            auto *currentReg = regCall->register_;
            getOrCreateStateBlock(currentReg);

            std::cerr << "    Register Write Detected (Statement): " << currentReg->name.name << std::endl;

            // 1. Check Arguments Directly
            std::cerr << "      Checking arguments for direct reads influencing write to " << currentReg->name.name << std::endl;
            for (const auto *arg : *mcs->methodCall->arguments) {
                std::cerr << "        Checking arg: " << arg->expression << std::endl;
                auto argReads = findRegisterReads(arg->expression);
                for (const auto *argReadReg : argReads) {
                    std::cerr << "          Found DIRECT read in arg: " << argReadReg->name.name << std::endl;
                    std::cerr << "          Adding ARG dependency: " << argReadReg->name.name << " -> " << currentReg->name.name << std::endl;
                    addRegisterDependency(argReadReg, currentReg);
                    getOrCreateStateBlock(argReadReg);
                    readsInCurrentAction.insert(argReadReg); // Track read for context
                }
            }

            // 2. Check Prior Reads in Action (Captures indirect dependencies via locals)
            // Create dependencies from all reads encountered *before* this write
            // within the current action scope to this write target.
            std::cerr << "      Checking prior reads in action influencing write to " << currentReg->name.name << std::endl;
            for (const auto *priorReadReg : readsInCurrentAction) {
                 // addRegisterDependency handles duplicates and prevents block1 == block2
                 std::cerr << "          Found PRIOR read: " << priorReadReg->name.name << std::endl;
                 std::cerr << "          Adding PRIOR READ dependency: " << priorReadReg->name.name << " -> " << currentReg->name.name << std::endl;
                 addRegisterDependency(priorReadReg, currentReg);
                 // Ensure prior read has a block, though it likely does
                 getOrCreateStateBlock(priorReadReg);
            }

            writesInCurrentAction.insert(currentReg);  // Track the write

        } else if (regCall->isRead()) {
            std::cerr << "    Register Read Detected (Statement): " << currentReg->name.name <<
            std::endl;

            readsInCurrentAction.insert(currentReg);
        }
    } else {
        std::cerr << "  Not a register operation call (Statement)." << std::endl;
        visit(mcs->methodCall);
    }
    return false;
}

bool StateBlockAnalyzer::preorder(const IR::MethodCallExpression *mce) {
    if (!currentAction) return true;

    if (auto regCall = RegisterCall::resolve(mce, refMap, typeMap)) {
        auto *currentReg = regCall->register_;
        getOrCreateStateBlock(currentReg);

        if (regCall->isRead()) {
            // std::cerr << "    Register Read Detected (Expression): " << currentReg->name.name <<
            // std::endl;
            readsInCurrentAction.insert(currentReg);  // Track the read
        }

    } else {
        // std::cerr << \"  Not a register operation call (Expression).\" << std::endl;
    }
    visit(mce->arguments);
    return false;
}

// Handle Assignments (e.g., meta.field = reg.read(); OR reg.write(some_value);)
bool StateBlockAnalyzer::preorder(const IR::AssignmentStatement *assign) {
    // std::cerr << \"Visiting AssignmentStatement: \" << assign << std::endl;
    if (!currentAction) {
        // std::cerr << \"  Not inside an action, skipping dependency analysis for assignment.\" <<
        // std::endl;
        return true;
    }

    const IR::Expression *lhs = assign->left;
    const IR::Expression *rhs = assign->right;

    // 1. Find all register reads on the RHS first
    auto rhsReads = findRegisterReads(rhs);
    for (const auto *readReg : rhsReads) {
        // std::cerr << \"    RHS Read Detected (Assign): \" << readReg->name.name << std::endl;
        readsInCurrentAction.insert(readReg);
        getOrCreateStateBlock(readReg);  // Ensure block exists
    }

    // 2. Visit the RHS expression fully *before* processing LHS write dependencies
    // This ensures all reads influencing the write are captured.
    visit(rhs);

    // Visit LHS - needed if LHS itself contains reads (e.g., array index)
    visit(lhs);

    return false;
}

// Handle If Statements - reads in condition affect writes in branches
bool StateBlockAnalyzer::preorder(const IR::IfStatement *ifStmt) {
    // std::cerr << \"Visiting IfStatement: \" << ifStmt << std::endl;
    if (!currentAction) return true;

    // 1. Find and track reads in the condition
    auto condReads = findRegisterReads(ifStmt->condition);
    // std::cerr << "    Condition reads: ";
    // for(auto r : condReads) { std::cerr << r->name.name << " "; }
    // std::cerr << std::endl;
    for (const auto *readReg : condReads) {
        // std::cerr << \"    Condition Read Detected: \" << readReg->name.name << std::endl;
        readsInCurrentAction.insert(readReg); 
        getOrCreateStateBlock(readReg);
    }
    // Visit the condition fully
    visit(ifStmt->condition);

    // 2. Capture reads state *before* visiting branches
    // Dependencies within branches should primarily stem from condition reads or reads before the IF.
    auto readsBeforeBranches = readsInCurrentAction;

    // --- TRUE BRANCH --- 
    std::set<const IR::Declaration_Instance *> writesInTrueBranch;

    readsInCurrentAction = readsBeforeBranches; 
    std::swap(writesInCurrentAction, writesInTrueBranch);
    visit(ifStmt->ifTrue);
    std::swap(writesInCurrentAction, writesInTrueBranch);
    writesInCurrentAction.insert(writesInTrueBranch.begin(), writesInTrueBranch.end());

    // Add dependencies: writes in TRUE branch depend on reads in the CONDITION
    // std::cerr << "    Adding IF-TRUE dependencies (CondReads -> BranchWrites):" << std::endl;
    for (const auto *writeReg : writesInTrueBranch) {
        // Ensure the write target has a block
        getOrCreateStateBlock(writeReg);
        for (const auto *condReadReg : condReads) { // ONLY check against condition reads
             // Ensure the condition read source has a block
             getOrCreateStateBlock(condReadReg);
             // std::cerr << "      " << condReadReg->name.name << " (cond) -> " << writeReg->name.name << " (true)" << std::endl;
             addRegisterDependency(condReadReg, writeReg);
        }
    }

    // --- FALSE BRANCH --- 
    std::set<const IR::Declaration_Instance *> writesInFalseBranch;
    if (ifStmt->ifFalse) {
        // Reset reads context to before branches again for False branch analysis
        readsInCurrentAction = readsBeforeBranches; 

        std::swap(writesInCurrentAction, writesInFalseBranch); // Isolate writes for this branch
        visit(ifStmt->ifFalse);
        std::swap(writesInCurrentAction, writesInFalseBranch); // Restore global writes, capture branch writes
        // Merge branch writes back into overall action writes
        writesInCurrentAction.insert(writesInFalseBranch.begin(), writesInFalseBranch.end());
        // Merge branch reads back into overall action reads (implicit)

        // Add dependencies: writes in FALSE branch depend on reads in the CONDITION
        // std::cerr << "    Adding IF-FALSE dependencies (CondReads -> BranchWrites):" << std::endl;
        for (const auto *writeReg : writesInFalseBranch) {
             // Ensure the write target has a block
             getOrCreateStateBlock(writeReg);
             for (const auto *condReadReg : condReads) { // ONLY check against condition reads
                 // Ensure the condition read source has a block
                 getOrCreateStateBlock(condReadReg);
                 // std::cerr << "      " << condReadReg->name.name << " (cond) -> " << writeReg->name.name << " (false)" << std::endl;
                 addRegisterDependency(condReadReg, writeReg);
             }
        }
    }

    return false;
}

bool StateBlockAnalyzer::preorder(const IR::P4Control *control) {
    std::cerr << "Visiting control block: " << control->name.name << std::endl;
    // Actions are analyzed when P4Action node is hit.
    // Could add logic here for control-level state if needed.
    return true;
}

// Entering an action - clear context
bool StateBlockAnalyzer::preorder(const IR::P4Action *action) {
    std::cerr << "Entering action: " << action->name.name << std::endl;
    currentAction = action;
    readsInCurrentAction.clear();
    writesInCurrentAction.clear();  // Reset for the new action
    visit(action->body);            // Visit the action body NOW

    // Store the results for later lookup by TableFinder
    actionRegisterUsage[action] = {readsInCurrentAction, writesInCurrentAction};
    std::cerr << "  Storing register usage for action: " << action->name.name << std::endl;
    std::cerr << "    Reads: " << readsInCurrentAction.size() << ", Writes: " << writesInCurrentAction.size() << std::endl;

    std::cerr << "Exiting action: " << action->name.name << std::endl;
    currentAction = nullptr;  // Clear context after visiting body
    return false;
}

bool StateBlockAnalyzer::preorder(const IR::P4Table *table) {
    // std::cerr << \"Visiting table: \" << table->name.name << std::endl;
    (void)table;
    return false;
}

// Merge blocks based on detected dependencies using SCC
void StateBlockAnalyzer::identifyStateBlocks() {
    std::cerr << "\n=== Identifying State Blocks using SCC ===" << std::endl;

    // 1. Initial Setup: Ensure every register has its own initial block.
    //    The main visitor pass already called getOrCreateStateBlock for declared registers.
    //    Map registers to their *initial* blocks. `registerToBlock` should hold this.
    //    Keep the initial list of blocks created during the visitor pass.
    std::vector<StateBlock *> initialBlocks = stateBlocks;
    std::map<const IR::Declaration_Instance*, StateBlock*> initialRegisterToBlock = registerToBlock;

    if (initialBlocks.empty()) {
        std::cerr << "WARNING: No initial blocks found before SCC analysis." << std::endl;
        return;
    }

    // 2. Build Adjacency List for Tarjan's Algorithm
    //    Nodes are the initial StateBlocks. Edges represent dependencies.
    std::map<StateBlock *, std::vector<StateBlock *>> adj;
    std::map<StateBlock *, size_t> blockToIndex; // Map initial blocks to integer indices
    size_t currentIndex = 0;
    for (StateBlock *block : initialBlocks) {
        blockToIndex[block] = currentIndex++;
        adj[block] = {}; // Initialize adjacency list entry
        // Add dependencies recorded during the visitor pass
        // Ensure dependencies point to the correct *initial* block representative
        for (StateBlock *dep : block->dependencies) {
             StateBlock *initialDepRep = initialRegisterToBlock.count(*dep->registers.begin()) ?
                                         initialRegisterToBlock.at(*dep->registers.begin()) : nullptr;
             if (initialDepRep && initialDepRep != block) { // Use initial map, avoid self-loops here
                 adj[block].push_back(initialDepRep);
             }
        }
        // Remove duplicates just in case
        std::sort(adj[block].begin(), adj[block].end());
        adj[block].erase(std::unique(adj[block].begin(), adj[block].end()), adj[block].end());
    }

    // 3. Tarjan's Algorithm Implementation
    std::map<StateBlock *, int> ids;         // Discovery time (id) for each node
    std::map<StateBlock *, int> lowLinks;    // Lowest id reachable (including self)
    std::vector<StateBlock *> stack;         // Stack for Tarjan's algorithm
    std::map<StateBlock *, bool> onStack;    // Check if node is on stack
    int currentId = 0;
    std::vector<std::vector<StateBlock *>> allSccs; // To store the resulting SCCs

    std::function<void(StateBlock *)> tarjanDfs =
        [&](StateBlock *at) {
        stack.push_back(at);
        onStack[at] = true;
        ids[at] = lowLinks[at] = currentId++;

        for (StateBlock *to : adj[at]) {
            if (ids.find(to) == ids.end()) { // Not visited
                tarjanDfs(to);
            }
            // Need to check if 'to' is still on stack AFTER the recursive call returns
            // because 'to' might belong to an SCC already popped.
            if (onStack.count(to) && onStack[to]) {
                lowLinks[at] = std::min(lowLinks[at], lowLinks[to]);
            }
        }

        // Found the root of an SCC
        if (ids[at] == lowLinks[at]) {
            std::vector<StateBlock *> currentScc;
            while (!stack.empty()) {
                StateBlock *node = stack.back();
                stack.pop_back();
                onStack[node] = false;
                currentScc.push_back(node);
                lowLinks[node] = ids[at];
                if (node == at) break;
            }
            allSccs.push_back(currentScc);
        }
    };

    // Run Tarjan's DFS for all unvisited nodes
    for (StateBlock *block : initialBlocks) {
        if (ids.find(block) == ids.end()) {
            tarjanDfs(block);
        }
    }
    std::cerr << "Found " << allSccs.size() << " Strongly Connected Components." << std::endl;

    // 4. Create Final State Blocks based on SCCs
    std::vector<StateBlock *> finalBlocks;
    std::map<const IR::Declaration_Instance *, StateBlock *> finalRegisterToBlock; // New map for final blocks
    std::map<StateBlock *, StateBlock *> initialToFinalBlockMap; // Map initial block ptrs to final block ptrs
    std::map<StateBlock *, size_t> finalBlockToIndex; // Map final block ptr to its index for logging

    for (const auto &scc : allSccs) {
        if (scc.empty()) continue;

        // Create a new block for this SCC
        StateBlock *finalBlock = new StateBlock();
        finalBlocks.push_back(finalBlock);
        finalBlockToIndex[finalBlock] = finalBlocks.size() - 1; // Store index
        std::cerr << "  Creating Final Block " << finalBlockToIndex[finalBlock] << " for SCC with " << scc.size() << " initial block(s):";

        // Merge registers and flow groups from all initial blocks in the SCC
        for (StateBlock *initialBlock : scc) {
             std::cerr << " {";
             for(auto r : initialBlock->registers) std::cerr << r->name.name << " ";
             std::cerr << "}";
            initialToFinalBlockMap[initialBlock] = finalBlock; // Map initial to its final SCC block
            for (const auto *reg : initialBlock->registers) {
                if (finalBlock->registers.find(reg) == finalBlock->registers.end()) {
                    finalBlock->addRegister(reg);
                    finalRegisterToBlock[reg] = finalBlock; // Update register map
                }
            }
            finalBlock->flowGroups.insert(initialBlock->flowGroups.begin(), initialBlock->flowGroups.end());
        }
        std::cerr << std::endl;
    }

    // 5. Recompute Dependencies between Final Blocks
    // Iterate through the original dependencies. If a dependency crosses SCC boundaries,
    // add a dependency between the corresponding final blocks.
    std::cerr << "Recomputing dependencies between final blocks..." << std::endl;
    for (StateBlock *initialBlock : initialBlocks) {
         StateBlock *finalSourceBlock = initialToFinalBlockMap[initialBlock];
         for (StateBlock *initialDep : adj[initialBlock]) { // Use adjacency list built earlier
             StateBlock *finalTargetBlock = initialToFinalBlockMap[initialDep];
             if (finalSourceBlock != finalTargetBlock) { // Check if dependency is between different SCCs
                 // Add dependency if not already present
                 bool exists = false;
                 for(auto* existingDep : finalSourceBlock->dependencies) {
                    if (existingDep == finalTargetBlock) {
                        exists = true;
                        break;
                    }
                 }
                 if (!exists) {
                    std::cerr << "  Adding final dependency: Block " << finalBlockToIndex[finalSourceBlock]
                              << " -> Block " << finalBlockToIndex[finalTargetBlock] << std::endl;
                    finalSourceBlock->addDependency(finalTargetBlock);
                 }
             }
         }
    }

    // Clean up old initial blocks (if not using smart pointers)
    for (StateBlock* block : initialBlocks) {
        (void)block;
    }

    // Replace the analyzer's state with the new final blocks and map
    stateBlocks = finalBlocks;
    registerToBlock = finalRegisterToBlock;

    std::cerr << "\nFinal state blocks after SCC merging: (" << stateBlocks.size() << " blocks)"
              << std::endl;
}


StateBlock *StateBlockAnalyzer::getRepresentativeBlock(const IR::Declaration_Instance *inst) const {
    auto it = registerToBlock.find(inst);
    if (it == registerToBlock.end()) {
        // std::cerr << "WARNING: Register " << inst->name.name << " not found in registerToBlock map." << std::endl;
        return nullptr; // Register not tracked
    }
    return it->second;
}

// Overload for finding representative of a block pointer (used in dependency checks)
StateBlock *StateBlockAnalyzer::getRepresentativeBlock(const StateBlock *block) const {
     // Find the block in the final list
     for(const auto* finalBlock : stateBlocks) {
        if (finalBlock == block) {
            return const_cast<StateBlock*>(block); // Found it in the final list
        }
     }
     if (block && !block->registers.empty()) {
        return getRepresentativeBlock(*block->registers.begin());
     }
     return nullptr; // Block pointer doesn't match any final block
}

// Merge block2 into block1 - **This function is now OBSOLETE** due to SCC merging
// Keep it for now to avoid breaking other potential callsites, but mark as deprecated/unused.
void StateBlockAnalyzer::mergeStateBlocks(StateBlock *block1, StateBlock *block2) {
     std::cerr << "WARNING: mergeStateBlocks called but is obsolete due to SCC merging. No action taken." << std::endl;
     (void)block1;
     (void)block2;
}

// Generate DOT graph
void StateBlockAnalyzer::generateDependencyGraph(const char *outFile) const {
    std::ofstream dot(outFile);
    if (!dot.is_open()) {
        std::cerr << "ERROR: Could not open DOT file for writing: " << outFile << std::endl;
        return;
    }
    dot << "digraph StateBlocks {\n";
    dot << "  compound=true; // Allow edges to clusters\n";
    dot << "  rankdir=LR;\n";
    dot << "  node [shape=box, style=filled, fillcolor=lightblue];\n";
    dot << "  edge [arrowhead=vee];\n\n";

    // Create a mapping from block pointer to a safe cluster ID
    std::map<const StateBlock *, std::string> blockToClusterId;
    for (size_t i = 0; i < stateBlocks.size(); ++i) {
        blockToClusterId[stateBlocks[i]] = "cluster_" + std::to_string(i);
    }

    // Create subgraphs (clusters) for each state block
    for (size_t i = 0; i < stateBlocks.size(); i++) {
        const StateBlock *block = stateBlocks[i];
        std::string clusterId = blockToClusterId.at(block);
        dot << "  subgraph " << clusterId << " {\n";
        dot << "    label = \"State Block " << i << "\";\n";
        dot << "    style = filled;\n";
        dot << "    fillcolor = lightgrey; // Color the subgraph background\n";
        dot << "    node [fillcolor=lightblue]; // Node color inside cluster\n";

        // Add nodes for each register within the block
        std::vector<cstring> regNames;
        for (auto reg : block->registers) {
            regNames.push_back(reg->name.name);
        }
        std::sort(regNames.begin(), regNames.end());
        for (const auto &name : regNames) {
             // Create a unique node ID for the register
             std::string regNodeId = clusterId + "_" + name.c_str(); 
             dot << "    \"" << regNodeId << "\" [label=\"" << name << "\"];\n";
        }
        dot << "  }\n\n";
    }

    // Add edges for dependencies between final blocks (clusters)
    std::set<std::pair<std::string, std::string>> addedEdges; // Avoid duplicate edges
    for (const auto &sourceBlock : stateBlocks) {
        std::string sourceClusterId = blockToClusterId.at(sourceBlock);
        for (const StateBlock *depBlock : sourceBlock->dependencies) {
            // Ensure dependency target is a valid final block
            if (blockToClusterId.count(depBlock)) {
                 std::string targetClusterId = blockToClusterId.at(depBlock);
                 if (sourceClusterId != targetClusterId && 
                     addedEdges.find({sourceClusterId, targetClusterId}) == addedEdges.end()) {
                    // Use lhead and ltail to connect edges to clusters
                    // Pick representative nodes within clusters if needed, or just connect clusters
                    dot << "  " << sourceClusterId << " -> " << targetClusterId 
                        << " [ltail=\"" << sourceClusterId << "\", lhead=\"" << targetClusterId << "\"];\n";
                    addedEdges.insert({sourceClusterId, targetClusterId});
                 }
            } else {
                 std::cerr << "WARNING: Dependency target block pointer mismatch during DOT generation." << std::endl;
            }
        }
    }

    // Add intra-block edges for SCCs with > 1 register
    dot << "\n  // Intra-Block Dependencies (Cycles)\n";
    for (const auto &block : stateBlocks) {
        if (block->registers.size() > 1) {
            std::string clusterId = blockToClusterId.at(block);
            // Convert set to vector for easier iteration over pairs
            std::vector<const IR::Declaration_Instance *> regs(block->registers.begin(), block->registers.end());
            // Use a set to track added edges to avoid duplicates (A->B and B->A)
            std::set<std::pair<const IR::Declaration_Instance *, const IR::Declaration_Instance *>> addedIntraEdges;

            for (size_t i = 0; i < regs.size(); ++i) {
                for (size_t j = i + 1; j < regs.size(); ++j) {
                    const IR::Declaration_Instance *regA = regs[i];
                    const IR::Declaration_Instance *regB = regs[j];
                    
                    // Ensure consistent pair ordering for the set
                    const IR::Declaration_Instance *first = (regA < regB) ? regA : regB;
                    const IR::Declaration_Instance *second = (regA < regB) ? regB : regA;

                    if (addedIntraEdges.find({first, second}) == addedIntraEdges.end()) {
                        std::string nodeAId = clusterId + "_" + regA->name.name.c_str();
                        std::string nodeBId = clusterId + "_" + regB->name.name.c_str();
                        // Draw blue bidirectional edge for internal cycle indication
                        dot << "  \"" << nodeAId << "\" -> \"" << nodeBId << "\" [dir=both, style=solid, color=blue];\n";
                        addedIntraEdges.insert({first, second});
                    }
                }
            }
        }
    }

    // Add flow group information as separate nodes connected to block clusters
    dot << "\n  // Flow Groups Subgraph \n";
    dot << "  subgraph cluster_flow_groups {\n";
    dot << "    label=\"Flow Groups\";\n";
    dot << "    node [shape=ellipse, style=filled, fillcolor=lightgreen];\n";

    std::set<cstring> allFlowGroups;
    std::map<cstring, std::string> safeGroupIds;
    int fg_count = 0;
    for (const auto &block : stateBlocks) {
        for (const auto &group : block->flowGroups) {
            if (allFlowGroups.find(group) == allFlowGroups.end()) {
                allFlowGroups.insert(group);
                std::string safeId = "fg_" + std::to_string(fg_count++);
                safeGroupIds[group] = safeId;
                dot << "    " << safeId << " [label=\"" << group << "\"];\n";
            }
        }
    }
    dot << "  }\n";

    // Connect flow groups to state block clusters
    dot << "\n  // Flow Group Connections\n";
    std::set<std::pair<std::string, std::string>> addedFgEdges;
    for (const auto &block : stateBlocks) {
        std::string blockClusterId = blockToClusterId.at(block);
        for (const auto &group : block->flowGroups) {
            if (safeGroupIds.count(group)) {
                std::string safeId = safeGroupIds[group];
                if (addedFgEdges.find({safeId, blockClusterId}) == addedFgEdges.end()) {
                    dot << "  " << safeId << " -> " << blockClusterId
                        << " [style=dashed, arrowhead=none, lhead=\"" << blockClusterId << "\"];\n";
                    addedFgEdges.insert({safeId, blockClusterId});
                }
            }
        }
    }

    // Add legend subgraph
    dot << "\n  subgraph cluster_legend {\n";
    dot << "    label = \"Legend\";\n";
    dot << "    rank = sink; // Try to place legend at the bottom\n";
    dot << "    node [shape=plaintext, fontcolor=black];\n";
    dot << "    key [label=<\n";
    dot << "      <table border=\"0\" cellborder=\"1\" cellspacing=\"0\" cellpadding=\"4\">\n";
    dot << "        <tr><td align=\"right\">State Block (Cluster)</td><td bgcolor=\"lightgrey\"></td></tr>\n";
    dot << "        <tr><td align=\"right\">Register</td><td><font color=\"black\"><table border=\"0\" cellborder=\"1\" cellspacing=\"0\" bgcolor=\"lightblue\"><tr><td>RegName</td></tr></table></font></td></tr>\n";
    dot << "        <tr><td align=\"right\">Flow Group</td><td><font color=\"black\"><table border=\"0\" cellborder=\"1\" cellspacing=\"0\" shape=\"ellipse\" bgcolor=\"lightgreen\"><tr><td>FGName</td></tr></table></font></td></tr>\n";
    dot << "        <tr><td align=\"right\">Dependency</td><td><font color=\"black\">&#8594;</font> (Solid Line)</td></tr>\n"; // Unicode right arrow
    dot << "        <tr><td align=\"right\">Flow Group Association</td><td><font color=\"black\">--</font> (Dashed Line)</td></tr>\n";
    dot << "      </table>\n";
    dot << "    >];\n";
    dot << "  }\n";

    dot << "}\n";
    dot.close();
    std::cerr << "Generated dependency graph: " << outFile << std::endl;
}

// Dump analysis results
void StateBlockAnalyzer::dumpAnalysis() const {
    std::cout << "\nDetailed State Block Analysis:" << std::endl;
    std::cout << "============================" << std::endl;

    if (stateBlocks.empty()) {
        std::cout << "WARNING: No final state blocks found!" << std::endl;
        std::cout << "(Expected 3 registers: DipCntr, MinDip, MinLoad)" << std::endl;
        return;
    }

    // Create a mapping from block pointer to index for consistent naming in output
    std::map<const StateBlock *, size_t> blockToIndex;
    for (size_t i = 0; i < stateBlocks.size(); ++i) {
        blockToIndex[stateBlocks[i]] = i;
    }

    for (size_t i = 0; i < stateBlocks.size(); i++) {
        const StateBlock *block = stateBlocks[i];
        std::cout << "\nState Block " << i << ":" << std::endl;
        std::cout << "-------------" << std::endl;

        std::cout << "Registers:" << std::endl;
        std::vector<cstring> regNames;
        for (auto reg : block->registers) {
            regNames.push_back(reg->name.name);
        }
        std::sort(regNames.begin(), regNames.end());
        for (const auto &name : regNames) {
            std::cout << "  - " << name << std::endl;
        }

        std::cout << "Dependencies (Outgoing):" << std::endl;
        std::set<size_t> printedDepIndices;  // Avoid duplicate dependency prints per block
        bool hasDeps = false;
        for (auto dep : block->dependencies) {
            // Find the representative block of the dependency target
            const StateBlock *repDep = getRepresentativeBlock(dep);
            if (repDep) {  // Check if representative is valid
                auto depIt = blockToIndex.find(repDep);
                if (depIt != blockToIndex.end()) {
                    size_t depIndex = depIt->second;
                    // Avoid self-references in output and duplicates
                    if (depIndex != i &&
                        printedDepIndices.find(depIndex) == printedDepIndices.end()) {
                        std::cout << "  - Depends on Block " << depIndex << " containing:";
                        hasDeps = true;
                        std::vector<cstring> depRegNames;
                        for (auto reg : repDep->registers) {
                            depRegNames.push_back(reg->name.name);
                        }
                        std::sort(depRegNames.begin(), depRegNames.end());
                        for (const auto &name : depRegNames) {
                            std::cout << " " << name;
                        }
                        std::cout << std::endl;
                        printedDepIndices.insert(depIndex);
                    }
                } else {
                    // This case should ideally not happen if map is consistent
                    std::cout << "  - WARNING: Depends on a block not found in the final map."
                              << std::endl;
                    hasDeps = true;  // Still indicate a dependency was found
                }
            } else {
                // Dependency target block pointer was invalid or couldn't be resolved
                std::cout << "  - WARNING: Contains dependency to an invalid/unresolved block."
                          << std::endl;
                hasDeps = true;
            }
        }
        if (!hasDeps) {
            std::cout << "  INFO: No outgoing dependencies detected for this block." << std::endl;
        }

        std::cout << "Flow Groups:" << std::endl;
        if (block->flowGroups.empty()) {
            std::cout << "  INFO: No flow groups mapped to this block." << std::endl;
        } else {
            std::vector<cstring> groupNames(block->flowGroups.begin(), block->flowGroups.end());
            std::sort(groupNames.begin(), groupNames.end());
            for (const auto &group : groupNames) {
                std::cout << "  - " << group << std::endl;
            }
        }
    }
}

// Phase 3: Map Flow Groups (Tables) to State Blocks
void StateBlockAnalyzer::mapFlowGroups() {
    std::cerr << "\n=== Mapping Flow Groups ===" << std::endl;
    std::cerr << "\nMapping flow groups to state blocks..." << std::endl;
    std::cerr << "Expected mappings: (Reference only)" << std::endl;
    std::cerr << "  - connTbl -> state blocks containing registers used in its actions"
              << std::endl;

    // Need to find P4Table declarations within the program structure
    // This might involve traversing Packages, Controls, etc.
    class TableFinder : public Inspector {
        StateBlockAnalyzer *analyzer;
        bool foundConnTbl = false;

     public:
        TableFinder(StateBlockAnalyzer *a) : analyzer(a) {}
        bool getFoundConnTbl() const { return foundConnTbl; }

        bool preorder(const IR::P4Table *table) override {
            std::cerr << "\n>>> DEBUG: Entered TableFinder::preorder for table: " << table->name.name << std::endl;

            // Use startsWith to handle potential suffixes like _0
            if (table->name.name.startsWith("connTbl")) {
                foundConnTbl = true;
                std::cerr << "  INFO: Found expected table starting with 'connTbl' (local name: "
                          << table->name.name << ")." << std::endl;
            }

            const IR::ActionList *actionList = table->getActionList();
            if (!actionList) {
                 std::cerr << "  >>> DEBUG: ActionList is NULL for table " << table->name.name << ". Skipping action processing." << std::endl;
                 return false;
            }
            std::cerr << "  >>> DEBUG: ActionList found for table " << table->name.name << ". Processing actions..." << std::endl;

            for (const auto *actionElement : actionList->actionList) {
                std::cerr << "    >>> DEBUG: Processing action element expression kind: " << actionElement->expression->node_type_name() << std::endl;
                
                const IR::Path* actionPath = nullptr;
                if (auto pathExpr = actionElement->expression->to<IR::PathExpression>()) {
                    // Original assumption (may still occur in some P4 versions/syntaxes)
                    actionPath = pathExpr->path;
                    std::cerr << "    >>> DEBUG: Found PathExpression for action." << std::endl;
                } else if (auto mce = actionElement->expression->to<IR::MethodCallExpression>()) {
                    // Handle MethodCallExpression found in log
                    if (auto mcePathExpr = mce->method->to<IR::PathExpression>()) {
                        actionPath = mcePathExpr->path;
                        std::cerr << "    >>> DEBUG: Found MethodCallExpression, extracted path for action." << std::endl;
                    } else {
                         std::cerr << "    >>> DEBUG: MethodCallExpression's method is not a PathExpression. Skipping." << std::endl;
                    }
                } else {
                     std::cerr << "    >>> DEBUG: Action element expression is neither PathExpression nor MethodCallExpression. Skipping." << std::endl;
                }
                
                if (!actionPath) {
                    continue;
                }

                auto actionDeclNode = analyzer->refMap->getDeclaration(actionPath, true);
                const IR::P4Action *actionDecl =
                    actionDeclNode ? actionDeclNode->to<IR::P4Action>() : nullptr;

                if (actionDecl) {
                    std::cerr << "  Checking action referenced by table: " << actionDecl->name.name
                              << std::endl;
                    // Find register ops *within* this action's body
                    std::set<const IR::Declaration_Instance *> actionReads;
                    std::set<const IR::Declaration_Instance *> actionWrites;

                    if (analyzer->actionRegisterUsage.count(actionDecl)) {
                        actionReads = analyzer->actionRegisterUsage.at(actionDecl).first;
                        actionWrites = analyzer->actionRegisterUsage.at(actionDecl).second;
                        std::cerr << "    Retrieved stored register usage for action: " << actionDecl->name.name << std::endl;
                    } else {
                        std::cerr << "    WARNING: No stored register usage found for action: " << actionDecl->name.name << ". Flow group mapping might be incomplete." << std::endl;
                    }
                    // Log found registers (using retrieved data)
                    std::cerr << "      Registers read by action '" << actionDecl->name.name << "':";
                    for(const auto* r : actionReads) std::cerr << " " << r->name.name;
                    std::cerr << std::endl;
                    std::cerr << "      Registers written by action '" << actionDecl->name.name << "':";
                    for(const auto* w : actionWrites) std::cerr << " " << w->name.name;
                    std::cerr << std::endl;

                    std::set<const IR::Declaration_Instance *> actionOps = actionReads;
                    actionOps.insert(actionWrites.begin(), actionWrites.end());

                    // Add flow group to the *final* representative block for each register
                    for (const auto *regInst : actionOps) {
                        StateBlock *representativeBlock = analyzer->getRepresentativeBlock(regInst);
                        if (representativeBlock) {
                            // Use LOCAL table name for flow group identifier
                            if (representativeBlock->flowGroups.find(table->name.name) ==
                                representativeBlock->flowGroups.end()) {
                                std::cerr << "    Attempting to map flow group '" << table->name.name
                                          << "' to block containing:";
                                for(const auto* r : representativeBlock->registers) std::cerr << " " << r->name.name;
                                std::cerr << std::endl;

                                representativeBlock->flowGroups.insert(
                                    table->name.name);  // Insert local name
                            } else {
                                 std::cerr << "    Skipping mapping: Flow group '" << table->name.name
                                           << "' already mapped to block containing:";
                                 for(const auto* r : representativeBlock->registers) std::cerr << " " << r->name.name;
                                 std::cerr << std::endl;
                            }
                        } else {
                            std::cerr << "    WARNING: Register " << regInst->name.name
                                      << " used in action " << actionDecl->name.name
                                      << " not found in any final state block." << std::endl;
                        }
                    }
                } else {
                    std::cerr << "  WARNING: Could not resolve action declaration for: "
                              << actionPath->name << std::endl;
                }
            }
            return false;  // Don't traverse inside table definition further
        }
    };

    TableFinder tableFinder(this);
    program->apply(tableFinder);  // Find tables anywhere in the program

    if (!tableFinder.getFoundConnTbl()) {
        std::cerr << "WARNING: Expected table 'connTbl' not found during flow group mapping."
                  << std::endl;
    }
}

// Add a dependency reg1 -> reg2
void StateBlockAnalyzer::addRegisterDependency(const IR::Declaration_Instance *reg1,
                                               const IR::Declaration_Instance *reg2) {
    if (reg1 == reg2) return;  // Don't add self-dependencies

    // Find the *initial* representative blocks for these registers
    // This function is called *before* SCC merging.
    auto block1 = getOrCreateStateBlock(reg1);
    auto block2 = getOrCreateStateBlock(reg2);

    // If either register isn't in a block yet, or
    // if they are already in the same block, no dependency needed between blocks.
    if (!block1 || !block2 || block1 == block2) return;

    // Check if dependency already exists to avoid duplicates in the vector
    bool exists = false;
    for (const auto *dep : block1->dependencies) {
        // Need to check against the representative block of the dependency target too!
        if (getOrCreateStateBlock(*dep->registers.begin()) == block2) {
            exists = true;
            break;
        }
    }

    if (!exists) {
        std::cerr << "Adding dependency: block(" << reg1->name.name << ") -> block("
                  << reg2->name.name << ")" << std::endl;
        block1->addDependency(block2);  // Add dependency to the target block
    } else {
        // std::cerr << "Skipping duplicate dependency: " << reg1->name.name << " -> " <<
        // reg2->name.name << std::endl;
    }
}

// Get or create a state block for a given register instance (initial creation)
StateBlock *StateBlockAnalyzer::getOrCreateStateBlock(const IR::Declaration_Instance *inst) {
    // This function is mainly for initial block creation when a register is declared
    // or first encountered. It doesn't handle finding the representative after merges.
    auto directIt = registerToBlock.find(inst);
    if (directIt != registerToBlock.end()) {
        return directIt->second;
    }

    // If no mapping exists, create a new block
    // std::cerr << "Creating new initial state block for register: " << inst->name.name <<
    // std::endl;
    auto block = new StateBlock();
    block->addRegister(inst);
    registerToBlock[inst] = block;
    stateBlocks.push_back(block);
    return block;
}

// --- Traffic Analysis ---

// Helper to convert dot-decimal IP string to uint32_t
// Returns 0 on error.
uint32_t ipStringToInt(const std::string& ip_str) {
    struct in_addr addr;
    // Use inet_pton for IPv4 string to network address conversion
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        // Use ntohl for network to host byte order conversion
        return ntohl(addr.s_addr);
    } else {
        // std::cerr << "Warning: Failed to parse IP string: " << ip_str << std::endl;
        return 0;
    }
}

void StateBlockAnalyzer::calculateAndDumpFrequencies(
    const std::vector<TrafficRecord>& traffic,
    const ControlPlaneRules& rules)
{
    std::cerr << "\n=== Calculating State Block Access Frequencies ===" << std::endl;
    // Store counts per register: {read_count, write_count}
    std::map<const IR::Declaration_Instance*, std::pair<uint64_t, uint64_t>> registerAccessCounts;
    // Map action names to their IR declarations for easier lookup
    std::map<cstring, const IR::P4Action*> actionDeclarations;

    // Initialize counts for all registers found during analysis
    // and populate the action declaration map
    std::cerr << "Initializing counts for all detected registers..." << std::endl;
    for (const auto* block : this->stateBlocks) {
        for (const auto* reg : block->registers) {
            if (registerAccessCounts.find(reg) == registerAccessCounts.end()) {
                 registerAccessCounts[reg] = {0, 0};
                 std::cerr << "  Initializing counts for register: " << reg->name.name << std::endl;
            }
        }
    }
    // Populate action map from stored usage info
    std::cerr << "Mapping action names to declarations..." << std::endl;
    for (const auto& pair : this->actionRegisterUsage) {
         actionDeclarations[pair.first->name.name] = pair.first;
         std::cerr << "  Mapped action: " << pair.first->name.name << std::endl;
    }


    std::cerr << "Processing " << traffic.size() << " traffic records using action-based counting..." << std::endl;
    // Iterate through traffic records. Note: Counts are based on invoked actions.
    // Intra-action conditional logic is not simulated; if an action is invoked,
    // all registers potentially read/written by it (based on IR analysis) are counted.
    for (const auto& record : traffic) {

        // --- Determine Action Executed (Program-Specific Logic) ---
        // This part maps traffic/rules to a specific P4 action name.
        // For load_balancer.p4: Check connTbl based on srcIP.
        cstring executedActionName("nop");
        auto ruleIt = rules.find(record.srcIP);
        if (ruleIt != rules.end()) {
            // Rule hit implies 'setDip' action is the one associated with the matched entry
            // In a more general case, the control plane rules might specify the action name.
            executedActionName = cstring("setDip");
        }

        // Find the action declaration IR node
        auto actionDeclIt = actionDeclarations.find(executedActionName);
        if (actionDeclIt == actionDeclarations.end()) {
            // std::cerr << "Warning: Action '" << executedActionName << "' not found in declarations map. Skipping counts for this record." << std::endl;
            continue;
        }
        const IR::P4Action* actionDecl = actionDeclIt->second;

        // Find the register usage for this action
        auto usageIt = this->actionRegisterUsage.find(actionDecl);
        if (usageIt == this->actionRegisterUsage.end()) {
            // This shouldn't happen if actionDeclarations was populated correctly
             std::cerr << "Internal Warning: Usage info not found for mapped action '" << executedActionName << "'." << std::endl;
            continue;
        }

        const auto& usage = usageIt->second;
        const auto& reads = usage.first;
        const auto& writes = usage.second;

        // Increment read counts for registers read by this action
        for (const auto* reg : reads) {
            if (registerAccessCounts.count(reg)) {
                 registerAccessCounts.at(reg).first++;
            } else {
                 // Should not happen if initialization was complete
                 std::cerr << "Internal Warning: Register '" << reg->name.name << "' read by action '" << executedActionName << "' not found in count map." << std::endl;
            }
        }

        // Increment write counts for registers written by this action
        for (const auto* reg : writes) {
             if (registerAccessCounts.count(reg)) {
                 registerAccessCounts.at(reg).second++;
             } else {
                  // Should not happen if initialization was complete
                  std::cerr << "Internal Warning: Register '" << reg->name.name << "' written by action '" << executedActionName << "' not found in count map." << std::endl;
             }
        }
    }

    // Dump the results
    std::cout << "\n=== State Block Access Frequencies (per Register) ===" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << "(Note: Counts based on invoked actions. Intra-action conditionals not simulated.)" << std::endl;
    std::cout << "(Note: Atomicity column indicates requirement based on shared state access)" << std::endl;

    // Sort blocks by index for consistent output
    // Use range constructor for proper initialization
    std::vector<const StateBlock*> sortedBlocks(this->stateBlocks.begin(), this->stateBlocks.end());
    std::map<const StateBlock*, size_t> finalBlockToIndex;
    for(size_t i=0; i < sortedBlocks.size(); ++i) {
        finalBlockToIndex[sortedBlocks[i]] = i;
    }
    std::sort(sortedBlocks.begin(), sortedBlocks.end(),
        [&finalBlockToIndex](const auto* a, const auto* b) {
            size_t indexA = finalBlockToIndex.count(a) ? finalBlockToIndex.at(a) : SIZE_MAX;
            size_t indexB = finalBlockToIndex.count(b) ? finalBlockToIndex.at(b) : SIZE_MAX;
            return indexA < indexB;
    });

    for(const auto* block : sortedBlocks) {
        if (!finalBlockToIndex.count(block)) {
             std::cerr << "Warning: Skipping frequency output for untracked block." << std::endl;
             continue;
        }
        size_t blockIndex = finalBlockToIndex.at(block);
        std::cout << "\nState Block " << blockIndex << ":" << std::endl;

        // Sort registers within the block for consistent output
        std::vector<const IR::Declaration_Instance*> regsInBlock(block->registers.begin(), block->registers.end());
        std::sort(regsInBlock.begin(), regsInBlock.end(), [](const auto* a, const auto* b) {
            return a->name.name < b->name.name;
        });

        std::cout << "  Register     | Read Count  | Write Count | Atomic" << std::endl;
        std::cout << "  -------------|-------------|-------------|--------" << std::endl;
        for (const auto* reg : regsInBlock) {
            if (registerAccessCounts.count(reg)) {
                 const auto& counts = registerAccessCounts.at(reg);
                 printf("  %-12s | %-11lu | %-11lu | %-6s\n",
                        reg->name.name.c_str(), counts.first, counts.second, "Yes");
            } else {
                 // Should not happen if initialization was complete
                 printf("  %-12s | %-11s | %-11s | %-6s\n",
                        reg->name.name.c_str(), "N/A", "N/A", "N/A");
                 std::cerr << "Warning: No access count found for register: " << reg->name.name << std::endl;
            }
        }
    }
    std::cout << "========================================================" << std::endl;
}

// Implementation for checkMemoryRequirements
bool checkMemoryRequirements(const std::vector<const StateBlock*>& blocksToAllocate,
                               unsigned long availableMemoryBytes) {
    // Suppress unused parameter warnings for the stub implementation
    (void)blocksToAllocate;
    (void)availableMemoryBytes;

    if (false) {
        std::cout << "Checking memory for " << blocksToAllocate.size() << " blocks.";
        std::cout << "Available memory: " << availableMemoryBytes << " bytes." << std::endl;
    }
    return true;
}

} // namespace P4