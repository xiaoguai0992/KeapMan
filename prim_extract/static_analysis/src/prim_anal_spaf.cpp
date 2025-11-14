#include <iostream>
#include "SVF-LLVM/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
// #include "SVF-LLVM/SVFSyzIRBuilder.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/Options.h"

#include "PDG.h"
#include "json.hpp"

SVF::PDG *SVF::PDG::progDg = nullptr;

using json = nlohmann::json;

typedef std::unordered_map<unsigned int, std::vector<std::string>> SyscallDefsTy;
SyscallDefsTy syscall_defs;

void parse_syscall_defs(std::string syscall_defs_path)
{
	std::ifstream file(syscall_defs_path);
	json j;
	file >> j;
	for (json::iterator it = j.begin(); it != j.end(); it ++)
	{
		unsigned int syscall_number = std::stoul(it.key());
		const json& args_json = it.value();
		std::vector<std::string> args;

		for (size_t i = 0; i < args_json.size(); i ++)
		{
			args.push_back(args_json[i].get<std::string>());
		}
		syscall_defs[syscall_number] = args;
	}
}

inline bool isICFGNodeHasInst(const SVF::ICFGNode *icfgNode)
{
	return SVF::SVFUtil::isa<SVF::IntraICFGNode>(icfgNode) ||
			SVF::SVFUtil::isa<SVF::CallICFGNode>(icfgNode) ||
			SVF::SVFUtil::isa<SVF::RetICFGNode>(icfgNode);
}

bool isInstSyscall(const llvm::Instruction *inst)
{
	if (const llvm::CallInst *callInst = llvm::dyn_cast<llvm::CallInst>(inst))
	{
		if (auto callee = callInst->getCalledFunction())
		{
			std::string calleeName = callee->getName().str();
			if (calleeName.compare(0, 8, "syscall_") == 0)
			{
				return true;
			}
		}
	}
	return false;
}

SVF::PDGNode *getOrCreatePDGNode(SVF::PDG *pdg, const llvm::Instruction *inst)
{
	SVF::PDGNode *node;
	SVF::NodeID nid = pdg->getNodeID(inst);
	if (!pdg->hasPDGNode(nid))
	{
		node = new SVF::PDGNode(nid, inst);
		if (isInstSyscall(inst))
			pdg->addPDGNode(node, true);
		else
			pdg->addPDGNode(node, false);
	}
	else
	{
		node = pdg->getPDGNode(nid);
	}
	return node;
}

void buildPDG(SVF::LLVMModuleSet *mset, SVF::PDG *pdg, SVF::ICFG *icfg, SVF::VFG *vfg, const SVF::FunObjVar *mainObj)
{
	SVF::Set<const SVF::ICFGNode*> visited;
	SVF::FIFOWorkList<const SVF::ICFGNode*> worklist;

	const SVF::ICFGNode *entry = icfg->getFunEntryICFGNode(mainObj);
	visited.insert(entry);
	worklist.push(entry);
	while (!worklist.empty())
	{
		const SVF::ICFGNode *cur = worklist.pop();

		/* Add data edges */
		if (isICFGNodeHasInst(cur))
		{
			const llvm::Instruction *inst = SVF::SVFUtil::cast<llvm::Instruction>(mset->getLLVMValue(cur));
			// llvm::outs() << "--------\n";
			// llvm::outs() << *inst << "\n";

			SVF::PDGNode *node = getOrCreatePDGNode(pdg, inst);

			for (const SVF::VFGNode *src : cur->getVFGNodes())
			{
				for (const SVF::VFGEdge *vfgEdge : src->getOutEdges())
				{
					const SVF::VFGNode* dst = vfgEdge->getDstNode();
					const SVF::ICFGNode* next = dst->getICFGNode();

					if (isICFGNodeHasInst(next))
					{
						const llvm::Instruction *instNext = SVF::SVFUtil::cast<llvm::Instruction>(mset->getLLVMValue(next));
						SVF::PDGNode *nodeNext = getOrCreatePDGNode(pdg, instNext);
						if (!pdg->hasPDGDataEdge(node, nodeNext) && node != nodeNext)
						{
							SVF::PDGDataEdge *dEdge = new SVF::PDGDataEdge(node, nodeNext);
							pdg->addPDGEdge(dEdge);
						}
					}
				}
			}
		}

		for (SVF::ICFGNode::const_iterator it = cur->OutEdgeBegin(),
				eit = cur->OutEdgeEnd(); it != eit; ++ it)
		{
			SVF::ICFGEdge *edge = *it;
			SVF::ICFGNode *succ = edge->getDstNode();

			/* Add control edges */
			if (isICFGNodeHasInst(cur) && isICFGNodeHasInst(succ))
			{
				const llvm::Instruction *inst = SVF::SVFUtil::cast<llvm::Instruction>(mset->getLLVMValue(cur));
				SVF::PDGNode *node = getOrCreatePDGNode(pdg, inst);

				const llvm::Instruction *instSucc = SVF::SVFUtil::cast<llvm::Instruction>(mset->getLLVMValue(succ));
				SVF::PDGNode *nodeSucc = getOrCreatePDGNode(pdg, instSucc);

				if (!pdg->hasPDGControlEdge(node, nodeSucc) && node != nodeSucc)
				{
					SVF::PDGControlEdge *cEdge = new SVF::PDGControlEdge(node, nodeSucc);
					pdg->addPDGEdge(cEdge);
				}
			}

			if (visited.find(succ) == visited.end())
			{
				visited.insert(succ);
				worklist.push(succ);
			}
		}
	}
}

void getSyscallCluster(SVF::PDG *pdg, int cur_clusterid,
		std::set<int> &syscall_cluster, std::set<int> &next_worklist)
{
	SVF::Set<int> visited;
	SVF::FIFOWorkList<int> worklist;
	visited.insert(cur_clusterid);
	worklist.push(cur_clusterid);
	while (!worklist.empty())
	{
		int cur_clusterid = worklist.pop();
		syscall_cluster.insert(cur_clusterid);
		for (SVF::NodeID nodeId : pdg->getNodeCluster(cur_clusterid))
		{
			SVF::PDGNode *node = pdg->getPDGNode(nodeId);
			for (SVF::PDGEdge *edge : node->getInEdges())
			{
				SVF::PDGNode *src = edge->getSrcNode();
				int next_clusterid = src->getLineNo();
				/* handle the case where the src node does not have a line number */
				if (next_clusterid == -1)
				{
					SVF::Set<SVF::PDGNode*> tmp_visited;
					SVF::FIFOWorkList<SVF::PDGNode*> tmp_worklist;
					tmp_visited.insert(src);
					tmp_worklist.push(src);
					while (!tmp_worklist.empty())
					{
						SVF::PDGNode *tmp_node = tmp_worklist.pop();
						for (SVF::PDGEdge *tmp_edge : tmp_node->getInEdges())
						{
							SVF::PDGNode *tmp_src = tmp_edge->getSrcNode();
							int tmp_clusterid = tmp_src->getLineNo();
							if (tmp_clusterid != -1)
							{
								if (!pdg->clusterHasSyscall(tmp_clusterid))
								{
									syscall_cluster.insert(tmp_clusterid);
									if (visited.find(tmp_clusterid) == visited.end())
									{
										visited.insert(tmp_clusterid);
										worklist.push(tmp_clusterid);
									}
								}
								else
								{
									next_worklist.insert(tmp_clusterid);
								}
							}
							else if (tmp_visited.find(tmp_src) == tmp_visited.end())
							{
								tmp_visited.insert(tmp_src);
								tmp_worklist.push(tmp_src);
							}
						} 
					}
				}
				/* if the src node is in another cluster */
				else if (next_clusterid != cur_clusterid)
				{
					if (!pdg->clusterHasSyscall(next_clusterid))
					{
						syscall_cluster.insert(next_clusterid);
						if (visited.find(next_clusterid) == visited.end())
						{
							visited.insert(next_clusterid);
							worklist.push(next_clusterid);
						}
					}
					else
					{
						next_worklist.insert(next_clusterid);
					}
				}
			}
		}
	}
}

bool succ_all_in(SVF::PDG *pdg, int clusterId, SVF::Set<int> &cluster)
{
	for (SVF::NodeID nodeId : pdg->getNodeCluster(clusterId))
	{
		SVF::PDGNode *node = pdg->getPDGNode(nodeId);
		for (SVF::PDGEdge *edge : node->getOutEdges())
		{
			SVF::PDGNode *dst = edge->getDstNode();
			int nextClusterId = dst->getLineNo();
			/* recursively handle the case where the dst node does not have a line number */
			if (nextClusterId == -1)
			{
				SVF::Set<SVF::PDGNode*> tmp_visited;
				SVF::FIFOWorkList<SVF::PDGNode*> tmp_worklist;
				tmp_visited.insert(dst);
				tmp_worklist.push(dst);
				while (!tmp_worklist.empty())
				{
					SVF::PDGNode *tmp_node = tmp_worklist.pop();
					for (SVF::PDGEdge *tmp_edge : tmp_node->getOutEdges())
					{
						SVF::PDGNode *tmp_dst = tmp_edge->getDstNode();
						int tmp_clusterid = tmp_dst->getLineNo();
						if (tmp_clusterid != -1)
						{
							if (tmp_clusterid != clusterId && cluster.find(tmp_clusterid) == cluster.end())
							{
								// SVF::SVFUtil::errs() << "cluster " << tmp_clusterid << " not visit.\n";
								return false;
							}
						}
						else if (tmp_visited.find(tmp_dst) == tmp_visited.end())
						{
							tmp_visited.insert(tmp_dst);
							tmp_worklist.push(tmp_dst);
						}
					} 
				}
			}
			else if (nextClusterId != clusterId && cluster.find(nextClusterId) == cluster.end())
			{
				// SVF::SVFUtil::errs() << "cluster " << nextClusterId << " not visit.\n";
				return false;
			}
		}
	}
	return true;
}

void splitFreeCluster(SVF::PDG *pdg, int free_lineno, int depDepth,
		std::set<int> &setup_cluster, std::set<int> &alloc_cluster, std::set<int> &free_cluster)
{
	SVF::PDGNode *freePDGNode = nullptr;
	for (auto it : *pdg)
	{
		SVF::PDGNode *node = it.second;
		if (node->getLineNo() == free_lineno)
		{
			freePDGNode = node;
			break;
		}
	}

	if (freePDGNode == nullptr)
	{
		SVF::SVFUtil::errs() << "Cannot find free syscall.\n";
		return;
	}

	SVF::Set<int> visited;
	// SVF::FIFOWorkList<int> worklist;
	std::priority_queue<int> worklist;
	visited.insert(free_lineno);
	worklist.push(free_lineno);
	/* put all the successors of free_lineno into visited */
	while(!worklist.empty())
	{
		// int cur_clusterid = worklist.pop();
		int cur_clusterid = worklist.top();
		worklist.pop();
		for (const SVF::NodeID nodeId : pdg->getNodeCluster(cur_clusterid))
		{
			SVF::PDGNode *src = pdg->getPDGNode(nodeId);
			for (SVF::PDGEdge *edge : src->getOutEdges())
			{
				SVF::PDGNode *dst = edge->getDstNode();
				int nextClusterId = dst->getLineNo();
				if (nextClusterId != cur_clusterid && visited.find(nextClusterId) == visited.end())
				{
					visited.insert(nextClusterId);
					worklist.push(nextClusterId);
				}
			}
		}
	}

	worklist.push(free_lineno);
	int depth = 0;

	while (!worklist.empty())
	{
		// int cur_clusterid = worklist.pop();
		int cur_clusterid = worklist.top();
		worklist.pop();
		std::set<int> cur_syscall_cluster;
		std::set<int> next_worklist;
		
		// SVF::SVFUtil::errs() << "Get syscall cluster " << cur_clusterid << ":\n";
		getSyscallCluster(pdg, cur_clusterid, cur_syscall_cluster, next_worklist);
		for (int clusterId : cur_syscall_cluster) {
			// SVF::SVFUtil::errs() << clusterId << ", ";
			visited.insert(clusterId);
		}
		// SVF::SVFUtil::errs() << "\n";
		// SVF::SVFUtil::errs() << "Next syscall cluster ";
		// for (int clusterId : next_worklist)
		// 	SVF::SVFUtil::errs() << clusterId << ", ";
		// SVF::SVFUtil::errs() << "\n";
		
		if (depth < depDepth
				&& alloc_cluster.find(cur_clusterid) == alloc_cluster.end()
				&& free_cluster.find(cur_clusterid) == free_cluster.end())
		{
			// SVF::SVFUtil::errs() << "Add syscall cluster at depth " << depth << "\n";
			for (int clusterId : cur_syscall_cluster)
			{
				if (alloc_cluster.find(clusterId) == alloc_cluster.end()
						&& free_cluster.find(clusterId) == free_cluster.end())
				{
					free_cluster.insert(clusterId);
				}
			}
			// free_cluster.insert(cur_syscall_cluster.begin(), cur_syscall_cluster.end());
			depth ++;
		}

		if (depth >= depDepth)
		{
			break;
		}

		/* toposort */
		for (int next_clusterid : next_worklist)
		{
			/* only 0-out-degree cluster will be the next cluster */
			// SVF::SVFUtil::errs() << "succ_all_in " << next_clusterid << " ";
			if (succ_all_in(pdg, next_clusterid, visited)) {
				worklist.push(next_clusterid);
				// SVF::SVFUtil::errs() << "try next " << next_clusterid << "\n";
			}
		}
	}
}

void splitPrepareCluster(SVF::PDG *pdg, int alloc_lineno,
	std::set<int> &alloc_cluster, std::set<int> &prepare_cluster)
{
	std::set<int> single_alloc_syscall_cluster;
	std::set<int> next_worklist;
	getSyscallCluster(pdg, alloc_lineno, single_alloc_syscall_cluster, next_worklist);

	for (int clusterId : alloc_cluster)
	{
		if (single_alloc_syscall_cluster.find(clusterId) == single_alloc_syscall_cluster.end())
		{
			prepare_cluster.insert(clusterId);
		}
	}

	alloc_cluster = single_alloc_syscall_cluster;
}

void recogParams(SVF::PDG *pdg, SVF::SVFG *svfg,
		const std::set<int> &src_cluster, const std::set<int> &dst_cluster,
		SVF::Set<const llvm::Value*> &params)
{
	SVF::LLVMModuleSet *mset = SVF::LLVMModuleSet::getLLVMModuleSet();
	for (auto it : *svfg)
	{
		const SVF::SVFGNode *svfgNode = it.second;
		const SVF::ICFGNode *icfgNode = svfgNode->getICFGNode();
		if (icfgNode == nullptr)
			continue;

		if (!isICFGNodeHasInst(icfgNode))
			continue;
		
		const llvm::Instruction *instSrc = SVF::SVFUtil::cast<llvm::Instruction>(mset->getLLVMValue(icfgNode));
		
		for (const SVF::SVFGEdge *svfgEdge : svfgNode->getOutEdges())
		{
			const SVF::SVFGNode *svfgDstNode = svfgEdge->getDstNode();
			if (!isICFGNodeHasInst(svfgDstNode->getICFGNode()))
				continue;
			
			const SVF::ICFGNode *icfgDstNode = svfgDstNode->getICFGNode();
			const llvm::Instruction *instDst = SVF::SVFUtil::cast<llvm::Instruction>(mset->getLLVMValue(icfgDstNode));
			
			SVF::NodeID srcId = pdg->getNodeID(instSrc);
			SVF::NodeID dstId = pdg->getNodeID(instDst);

			int srcClusterId = pdg->getPDGNode(srcId)->getLineNo();
			int dstClusterId = pdg->getPDGNode(dstId)->getLineNo();

			if (src_cluster.find(srcClusterId) != src_cluster.end() &&
					dst_cluster.find(dstClusterId) != dst_cluster.end())
			{
				const llvm::Value* val = mset->getLLVMValue(icfgNode);
				const llvm::Value* dstVal = mset->getLLVMValue(icfgDstNode);
				llvm::errs() << "SRC " << *val << " DST " << *dstVal << "\n";
				if (val) {
					params.insert(val);
				}
			}
		}
	}
}

std::string parseTypeRecursive(const llvm::DIType *type)
{
    if (auto *basic = llvm::dyn_cast<llvm::DIBasicType>(type))
	{
		return basic->getName().str();
	}

    if (auto *derived = llvm::dyn_cast<llvm::DIDerivedType>(type))
	{
        std::string tag;
        switch (derived->getTag()) {
            case llvm::dwarf::DW_TAG_pointer_type:
                tag = "*";
                break;
            case llvm::dwarf::DW_TAG_reference_type:
                tag = "&";
                break;
            case llvm::dwarf::DW_TAG_const_type:
                tag = "const ";
                break;
            case llvm::dwarf::DW_TAG_volatile_type:
                tag = "volatile ";
                break;
            default:
                tag = "";
                break;
        }

        std::string base = parseTypeRecursive(derived->getBaseType());
        if (derived->getTag() == llvm::dwarf::DW_TAG_pointer_type ||
            derived->getTag() == llvm::dwarf::DW_TAG_reference_type) {
            return base + tag;  // int*/int&
        } else {
            return tag + base;  // const int
        }
    }

    if (auto *composite = llvm::dyn_cast<llvm::DICompositeType>(type)) {
        return composite->getName().str(); // struct.Foo
    }

	// others
    return type->getName().str();
}

std::pair<std::string, std::string> getVarNameAndType(const llvm::Value *val)
{
	if (!val)
		return {"", ""};

    const llvm::Function *func = nullptr;

    if (const auto *inst = llvm::dyn_cast<llvm::Instruction>(val))
        func = inst->getFunction();
    else if (const auto *arg = llvm::dyn_cast<llvm::Argument>(val))
        func = arg->getParent();

    if (!func)
		return {"", ""};

    for (const auto &BB : *func)
	{
        for (const auto &I : BB)
		{
            if (auto *dbgDecl = llvm::dyn_cast<llvm::DbgDeclareInst>(&I))
			{
                if (dbgDecl->getAddress() == val)
				{
                    const llvm::DILocalVariable *var = dbgDecl->getVariable();
                    if (var)
                        return {var->getName().str(), parseTypeRecursive(var->getType())};
                }
            }
            if (auto *dbgVal = llvm::dyn_cast<llvm::DbgValueInst>(&I))
			{
                if (dbgVal->getValue() == val)
				{
                    const llvm::DILocalVariable *var = dbgVal->getVariable();
                    if (var)
                        return {var->getName().str(), parseTypeRecursive(var->getType())};
                }
            }
        }
    }

    return {"", ""};
}

std::string dirname(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return "";
    return path.substr(0, pos);
}

int main(int argc, char **argv)
{
	if (argc < 4) {
		llvm::errs() << "Usage: " << argv[0] << " <input.bc> <alloc_lineno> <free_lineno> <max_depth> <prim_sa.json>\n";
		return 1;
	}

	std::string workdir = dirname(argv[1]);

	std::vector<std::string> moduleNameVec;
	moduleNameVec.push_back(argv[1]);

	int alloc_lineno = std::stoi(argv[2]);
	int free_lineno = std::stoi(argv[3]);
	int max_depth = std::stoi(argv[4]);

	std::ifstream prim_sa_file(argv[5]);
	nlohmann::json prim;
	prim_sa_file >> prim;

	SVF::LLVMModuleSet *mset = SVF::LLVMModuleSet::getLLVMModuleSet();

	SVF::SVFModule *svf_module = SVF::LLVMModuleSet::buildSVFModule(moduleNameVec);
	llvm::Module *llvm_module = mset->getModule(0);
	llvm::errs() << "[*] buildSVFModule finish.\n";

	SVF::SVFIRBuilder builder(svf_module);
	SVF::SVFIR* pag = builder.build();
	llvm::errs() << "[*] PAG finish.\n";

	SVF::Andersen *ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);
	SVF::CallGraph *cg = ander->getCallGraph();
	SVF::ICFG *icfg = ander->getICFG();
	SVF::SVFGBuilder svfgBuilder;
	SVF::SVFG* svfg = svfgBuilder.buildFullSVFG(ander);
    svfg->dump(std::string(argv[1]) + std::string(".svfg"));

	const SVF::CallGraphNode *mainNode = cg->getCallGraphNode("main");
	const SVF::FunObjVar *mainObj = mainNode->getFunction();
	SVF::PDG *pdg = SVF::PDG::getPDG();
	buildPDG(mset, pdg, icfg, svfg, mainObj);
	pdg->dump(std::string(argv[1]) + std::string(".pdg"));
	SVF::SVFUtil::outs() << "\n";

	std::set<int> setup_cluster;
	std::set<int> alloc_cluster;

	for (int lineno : prim["setup"])
	{
		setup_cluster.insert(lineno);
	}
	for (int lineno : prim["alloc"])
	{
		alloc_cluster.insert(lineno);
	}

	json output_json;

	output_json["setup"] = json::array();
	for (int clusterId : setup_cluster)
	{
    	output_json["setup"].push_back(clusterId);
	}

	std::set<int> free_cluster;
	splitFreeCluster(pdg, free_lineno, max_depth,
			setup_cluster, alloc_cluster, free_cluster);
	output_json["free"] = json::array();
	for (int clusterId : free_cluster)
	{
		output_json["free"].push_back(clusterId);
	}

	std::set<int> prepare_cluster;
	splitPrepareCluster(pdg, alloc_lineno, alloc_cluster, prepare_cluster);

	output_json["alloc"] = json::array();
	for (int clusterId : alloc_cluster)
	{
		output_json["alloc"].push_back(clusterId);
	}

	output_json["prepare"] = json::array();
	for (int clusterId : prepare_cluster)
	{
		output_json["prepare"].push_back(clusterId);
	}

	// std::vector<std::string> prim_names = {"setup", "prepare", "alloc", "free"};
	// std::vector<std::set<int>*> prim_clusters = {&setup_cluster, &prepare_cluster, &alloc_cluster, &free_cluster};
	// for (int i = 0; i < prim_names.size(); i++)
	// {
	// 	for (int j = i + 1; j < prim_names.size(); j++)
	// 	{
	// 		std::string key = "params-" + prim_names[i] + "-" + prim_names[j];
	// 		output_json[key] = json::array();

	// 		SVF::Set<const llvm::Value*> params;
	// 		recogParams(pdg, svfg, *prim_clusters[i], *prim_clusters[j], params);

	// 		for (const llvm::Value *val : params)
	// 		{
	// 			const llvm::Value *var = nullptr;
	// 			if (!val->getType()->isVoidTy())
	// 			{
	// 				/* for instruction define a left value */
	// 				var = val;
	// 			}
	// 			else if (const llvm::StoreInst *store = llvm::dyn_cast<llvm::StoreInst>(val))
	// 			{
	// 				/* for store instruction */
	// 				var = store->getPointerOperand();
	// 			}
	// 			auto it = getVarNameAndType(var);
	// 			llvm::errs() << prim_names[i] << " " << prim_names[j] << " " << *val << "\n";
	// 			if (it.first != "")
	// 			{
	// 				llvm::errs() << it.first << " " << it.second << "\n";
	// 				output_json[key].push_back({
	// 					{"name", it.first},
	// 					{"type", it.second}
	// 				});
	// 			}
	// 		}
	// 	}
	// }

	std::ofstream primitive_out(workdir + std::string("/primitive_spaf.json"));
	primitive_out << output_json.dump(4);
	primitive_out.close();

	return 0;
}
