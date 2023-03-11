#include "llvm/ADT/MapVector.h"
// #include "llvm/IR/AbstractCallSite.h"
#include "llvm/IR/PassManager.h"

#include "llvm/Support/raw_ostream.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"

#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/ValueSymbolTable.h"

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "allocations.h"

#include <sqlite3.h>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unordered_map>
#include <regex>

using namespace llvm;

// 分析当前.o.llvm.bc 使用了哪些1全局变量,2函数和3struct类型
// LLVM 9.x

// opt-12  -load ~/Desktop/ko-experiments/IRKmalloc/libIRKmalloc.so  -irusage init/main.ll -disable-output
// opt-12  -load ~/Desktop/ko-experiments/IRKmalloc/libIRKmalloc.so  -irusage ~/Desktop/ko-experiments/linux-5.15.45-vanilla/out-llvm-12/init/main.ll -disable-output

// opt-12  -load ~/Desktop/ko-experiments/IRKmalloc/libIRKmalloc.so  -irusage ~/Desktop/ko-experiments/linux-5.15.45-vanilla/out-llvm-12/net/ipv6/mcast.ll -disable-output

namespace {
	bool isAllocation(std::string funcname) {
		bool res = false;
		for (auto &fn : alloc_funcs) {
			res |= std::regex_match(funcname, std::regex(fn));
			if (res) {
				return true;
			}
		}
		return false;
	}

	std::string stripPath(std::string filepath)
	{
		std::regex path_regex1("^.*/\\.\\.");
		// std::regex path_regex2("^\\./\\.\\./");
		std::string res = "";
		// if (std::regex_search(filepath, path_regex2)) {
		//     filepath = filepath.substr(2);
		// }
		if (std::regex_search(filepath, path_regex1)) {
			std::string delimiter = "/";
			std::string s = filepath;
			size_t pos = 0;
			std::vector<std::string> stk;
			std::string token;

			while ((pos = s.find(delimiter)) != std::string::npos) {
				token = s.substr(0, pos);
				s.erase(0, pos + delimiter.length());
				if (token == ".." && !stk.empty()) {
					stk.pop_back();
				} else {
					stk.push_back(token);
				}
				
			}

			for (auto x : stk) {
				res += x + "/";
			}
			res += s;
		} else {
			return filepath;
		}
		return res;
	}

    struct IRUsageModulePass : public llvm::ModulePass {
        static char ID;

        IRUsageModulePass() : ModulePass(ID) {}
        bool runOnModule(Module &M) override;
		std::string extractStruct(llvm::Type *t);
		std::vector<allocation*> record;
    };

	void stat(int res, int &success, int &failed, std::string sql)
    {
        if (res != SQLITE_OK)
        {
            failed++;
            // std::cout << "    failed :" << sql << std::endl;
        }
        else
        {
            success++;
        }
    }


    bool IRUsageModulePass::runOnModule(Module &M) {
        LLVMContext& CTX = M.getContext();
		std::string currFile = stripPath(M.getName().data());
		
		std::cout << currFile << std::endl;

		for (auto& F : M) {
			bool flag_alloc = false;
			Value *retv = nullptr;
			for (auto& BB : F) {
				for (auto& I : BB) {
					
					if (I.getOpcode() == Instruction::Call) {
                        auto *CB = dyn_cast<CallBase>(&I);
						Function *func = CB->getCalledFunction();
						
						if (func) {
							std::string fname = func->getName().data();
							if (fname.find("llvm") != std::string::npos || fname.find("trace_event_") != std::string::npos) {
								continue;
							}
							if (isAllocation(func->getName().data())) {
								flag_alloc = true;
								retv = &I;
							}
								
						}
						
                    }

					if (I.getOpcode() == Instruction::BitCast && flag_alloc) {
						for (Value *oprand : I.operands()) {
							if (retv == oprand) {
								BitCastInst *BCI = dyn_cast<BitCastInst>(&I);
								flag_alloc = false;

								// outs() << F.getName().data() << ":" << dyn_cast<CallBase>(retv)->getCalledFunction()->getName().data() 
								// 			<< ":" << extractStruct(BCI->getDestTy()) 
								// 			<< ":" << currFile << "\n";
								record.push_back(new allocation(
									dyn_cast<CallBase>(retv)->getCalledFunction()->getName().data(),
									F.getName().data(),
									currFile,
									extractStruct(BCI->getDestTy())
								));

								break;
							}
						}
					}

					
					
				}
			}
		
		}

		if (record.empty()) {
			return true;
		}

		sqlite3 *db;
		int res = sqlite3_open("allocations-0728.db", &db);
		int success = 0;
		int failed = 0;
		if (res) {
			std::cout << "    Database failed to open" << std::endl;
		} else {
			sqlite3_exec(db, record[0]->genDB().data(), nullptr, 0, nullptr);

			for (auto &al : record) {
				std::string sql = al->insert();
				res = sqlite3_exec(db, sql.data(), nullptr, 0, nullptr);
				stat(res, success, failed, sql);
			}
		}
		llvm::outs() << "    commited \e[32m" << success << " sqls, \e[31m" << failed << " failed\e[0m\n";

        sqlite3_close(db);



        return true;
    }

	std::string IRUsageModulePass::extractStruct(llvm::Type *t)
	{
		std::string Str;
		llvm::raw_string_ostream OS(Str);
		t->print(OS);
		std::string type_content = OS.str();
		std::regex struct_regex("^%struct\\.(\\w+).*");
		std::smatch matcher;
		if (std::regex_match(type_content, matcher, struct_regex))
		{
			// callee_structs.insert(matcher[1]);
			return matcher[1];
		}
		return type_content;
	}





char IRUsageModulePass::ID = 0;

static RegisterPass<IRUsageModulePass> X(
    "irusage",
    "IRUsage Module Pass",
    false,
    true
);
}
