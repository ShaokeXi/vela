#ifndef BACKENDS_TRAFFIC_ANALYSIS_REGISTER_CALL_H_
#define BACKENDS_TRAFFIC_ANALYSIS_REGISTER_CALL_H_

#include "ir/ir.h"
#include "frontends/p4/methodInstance.h"

namespace P4 {

// Represents a register method call (read/write)
class RegisterCall : public MethodInstance {
 public:
    const IR::Declaration_Instance* register_;  // The register instance being accessed
    const IR::MethodCallExpression* methodCall;  // The original method call

    RegisterCall(const IR::MethodCallExpression* methodCall, 
                const IR::IDeclaration* decl,
                const IR::Type_MethodBase* originalMethodType,
                const IR::Type_MethodBase* actualMethodType,
                const IR::Declaration_Instance* regInst)
        : MethodInstance(methodCall, decl, originalMethodType, actualMethodType), 
          register_(regInst), methodCall(methodCall) {}

    // Check if a method call is a register operation
    static const RegisterCall* resolve(const IR::MethodCallExpression* methodCall,
                                     ReferenceMap* refMap,
                                     TypeMap* typeMap) {
        if (methodCall == nullptr) return nullptr;

        // Check if this is a member expression on an extern register
        if (auto mem = methodCall->method->to<IR::Member>()) {
            auto mname = mem->member.name;
            if (mname == "read" || mname == "write") {
                // Get the expression being accessed (e.g., MinLoad)
                auto expr = mem->expr;
                if (auto path = expr->to<IR::PathExpression>()) {
                    auto decl = refMap->getDeclaration(path->path);
                    if (auto inst = decl->to<IR::Declaration_Instance>()) {
                        // Determine if this instance is a Register extern, specialized or canonical
                        bool isReg = false;
                        // 1) Specialized form: Register<...>
                        if (auto sp = inst->type->to<IR::Type_Specialized>()) {
                            if (auto base = sp->baseType->to<IR::Type_Name>()) {
                                if (base->path->name.name == "Register")
                                    isReg = true;
                            }
                        }
                        // 2) Canonical extern form: Type_Extern Register
                        if (!isReg) {
                            if (auto ext = inst->type->to<IR::Type_Extern>()) {
                                if (ext->name.name == "Register")
                                    isReg = true;
                            }
                        }
                        if (isReg) {
                            auto mi = MethodInstance::resolve(methodCall, refMap, typeMap);
                            return new RegisterCall(methodCall, decl,
                                        mi->originalMethodType,
                                        mi->actualMethodType,
                                        inst);
                        }
                    }
                }
            }
        }

        return nullptr;
    }

    // Helper to check if this is a read operation
    bool isRead() const {
        if (auto mem = methodCall->method->to<IR::Member>()) {
            return mem->member.name == "read";
        }
        return false;
    }

    // Helper to check if this is a write operation
    bool isWrite() const {
        if (auto mem = methodCall->method->to<IR::Member>()) {
            return mem->member.name == "write";
        }
        return false;
    }

    DECLARE_TYPEINFO(RegisterCall, MethodInstance);
};

}  // namespace P4

#endif  // BACKENDS_TRAFFIC_ANALYSIS_REGISTER_CALL_H_ 