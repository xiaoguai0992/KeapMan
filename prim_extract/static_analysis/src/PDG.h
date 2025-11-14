#ifndef SVF_PROGDG_H
#define SVF_PROGDG_h

#include "SVFIR/SVFIR.h"
#include <cmath>

void hueToRGB(double hue, int &r, int &g, int &b)
{
	double s = 1.0;
	double v = 1.0;
	double c = v * s;
	double x = c * (1 - std::abs(std::fmod(hue * 6, 2) - 1));
	double m = v - c;
	double rp, gp, bp;
	if (hue < 1.0 / 6)
		rp = c, gp = x, bp = 0;
	else if (hue < 2.0 / 6)
		rp = x, gp = c, bp = 0;
	else if (hue < 3.0 / 6)
		rp = 0, gp = c, bp = x;
	else if (hue < 4.0 / 6)
		rp = 0, gp = x, bp = c;
	else if (hue < 5.0 / 6)
		rp = x, gp = 0, bp = c;
	else
		rp = c, gp = 0, bp = x;
	r = static_cast<int>((rp + m) * 255);
	g = static_cast<int>((gp + m) * 255);
	b = static_cast<int>((bp + m) * 255);
}

namespace SVF
{
class PDGNode;

typedef GenericEdge<PDGNode> GenericPDGEdgeTy;

class PDGEdge : public GenericPDGEdgeTy
{
public:
	enum PDGEdgeK
	{
		CF,
		DD
	};

	PDGEdge(PDGNode *s, PDGNode *d, GEdgeFlag k) : GenericPDGEdgeTy(s, d, k)
	{
	}

	~PDGEdge()
	{
	}

	typedef GenericNode<PDGNode, PDGEdge>::GEdgeSetTy PDGEdgeSetTy;

	virtual const std::string toString() const
	{
		std::string str;
		std::stringstream rawstr(str);
		std::string kind = (getEdgeKind() == CF) ? "Control" : "Data";
		rawstr << "PDGEdge " << " [" << kind ;
		rawstr << getDstID() << "<--" << getSrcID() << "\t";
		return rawstr.str();
	}
};

class PDGControlEdge : public PDGEdge
{
public:
	PDGControlEdge(PDGNode *s, PDGNode *d) : PDGEdge(s, d, CF)
	{
	}

	~PDGControlEdge()
	{
	}

	static inline bool classof(const PDGControlEdge *)
	{
		return true;
	}

	static inline bool classof(const PDGEdge *edge)
	{
		return edge->getEdgeKind() == CF;
	}

	static inline bool classof(const GenericPDGEdgeTy *edge)
	{
		return edge->getEdgeKind() == CF;
	}
};

class PDGDataEdge : public PDGEdge
{
public:
	PDGDataEdge(PDGNode *s, PDGNode *d) : PDGEdge(s, d, DD)
	{
	}

	~PDGDataEdge()
	{
	}

	static inline bool classof(const PDGDataEdge *)
	{
		return true;
	}

	static inline bool classof(const PDGEdge *edge)
	{
		return edge->getEdgeKind() == DD;
	}

	static inline bool classof(const GenericPDGEdgeTy *edge)
	{
		return edge->getEdgeKind() == DD;
	}
};

typedef GenericNode<PDGNode, PDGEdge> GenericPDGNodeTy;

class PDGNode : public GenericPDGNodeTy
{
public:
	typedef PDGEdge::PDGEdgeSetTy::iterator iterator;
	typedef PDGEdge::PDGEdgeSetTy::const_iterator const_iterator;

	PDGNode(NodeID id, const llvm::Instruction *inst) : GenericPDGNodeTy(id, OtherKd)
	{
		_inst = inst;
		_lineno = -1;
		if (inst->getDebugLoc())
			_lineno = inst->getDebugLoc().getLine();
	}

	virtual const std::string toString() const
	{
		std::string str;
		llvm::raw_string_ostream rso(str);
		rso << "[" << getId() << "]" << " ";
		_inst->print(rso);

		return rso.str();
	}

	std::string getColor() const
	{
		if (_lineno == -1)
			return "#000000";
		
		double goldenRatio = 1.618033988749895;
		double hashValue = (_lineno * 131 % 16777216);
		double hue = std::fmod(hashValue * goldenRatio, 1.0);

		int r, g, b;
		hueToRGB(hue, r, g, b);
		std::stringstream ss;
		ss << "#" << std::hex 
			<< std::setw(2) << std::setfill('0') << r
			<< std::setw(2) << std::setfill('0') << g
			<< std::setw(2) << std::setfill('0') << b;
		return ss.str();
	}

	int getLineNo() const
	{
		return _lineno;
	}

	const llvm::Instruction *getInst() const
	{
		return _inst;
	}

	static inline bool classof(const PDGNode *)
	{
		return true;
	}

private:
	const llvm::Instruction *_inst;
	int _lineno;
};

typedef GenericGraph<PDGNode, PDGEdge> GenericPDGTy;

class PDG : public GenericPDGTy
{
public:
	typedef Map<NodeID, PDGNode *> PDGNodeIDToNodeMapTy;
	typedef Map<const llvm::Instruction *, NodeID> PDGInstToNodeIDTy;
	typedef std::set<NodeID> NodeClusterTy;
	typedef Map<int, NodeClusterTy> LineToNodeClusterMapTy;
	typedef PDGEdge::PDGEdgeSetTy PDGEdgeSetTy;
	typedef PDGNodeIDToNodeMapTy::iterator iterator;
	typedef PDGNodeIDToNodeMapTy::const_iterator const_iterator;
private:
	static PDG *progDg; ///< Singleton pattern here
	PDGInstToNodeIDTy _inst2nodeid;
	LineToNodeClusterMapTy _cluster;
	SVF::Map<int, bool> _cluster_has_syscall;
	uint32_t _next_nodeid = 0;
	PDG()
	{
	}
public:
	static inline PDG *getPDG()
	{
		if (progDg == nullptr)
		{
			progDg = new PDG();
		}
		return progDg;
	}
	
	static void releasePDG()
	{
		if (progDg)
		{
			delete progDg;
		}
		progDg = nullptr;
	}

	virtual ~PDG() {}

	inline PDGNode *getPDGNode(NodeID id) const
	{
		if (!hasPDGNode(id))
			return nullptr;
		return getGNode(id);
	}
	
	inline bool hasPDGNode(NodeID id) const
	{
		return hasGNode(id);
	}

	NodeID getNodeID(const llvm::Instruction *inst)
	{
		auto it = _inst2nodeid.find(inst);
		if (it != _inst2nodeid.end())
			return it->second;
		uint32_t id = ++ _next_nodeid;
		_inst2nodeid[inst] = id;
		return id;
	}

	bool hasPDGControlEdge(PDGNode *src, PDGNode *dst)
	{
		PDGEdge edge(src, dst, PDGEdge::CF);
		PDGEdge *outEdge = src->hasOutgoingEdge(&edge);
		PDGEdge *inEdge = dst->hasIncomingEdge(&edge);
		if (outEdge && inEdge)
		{
			assert(outEdge == inEdge && "edges not match");
			return true;
		}
		else
			return false;
	}

	bool hasPDGDataEdge(PDGNode *src, PDGNode *dst)
	{
		PDGEdge edge(src, dst, PDGEdge::DD);
		PDGEdge *outEdge = src->hasOutgoingEdge(&edge);
		PDGEdge *inEdge = dst->hasIncomingEdge(&edge);
		if (outEdge && inEdge)
		{
			assert(outEdge == inEdge && "edges not match");
			return true;
		}
		else
			return false;
	}

	PDGEdge *getPDGControlEdge(const PDGNode *src, const PDGNode *dst)
	{
		PDGEdge *edge = nullptr;
		size_t counter = 0;
		for (PDGEdge::PDGEdgeSetTy::iterator iter = src->OutEdgeBegin();
				iter != src->OutEdgeEnd(); ++ iter)
		{
			if (SVFUtil::isa<PDGControlEdge>(*iter) && (*iter)->getDstID() == dst->getId())
			{
				counter ++;
				edge = (*iter);
			}
		}
		assert(counter <= 1 && "More than 1 PDG edge between two nodes");
		return edge;
	}

	PDGEdge *getPDGDataEdge(const PDGNode *src, const PDGNode *dst)
	{
		PDGEdge *edge = nullptr;
		size_t counter = 0;
		for (PDGEdge::PDGEdgeSetTy::iterator iter = src->OutEdgeBegin();
				iter != src->OutEdgeEnd(); ++ iter)
		{
			if (SVFUtil::isa<PDGDataEdge>(*iter) && (*iter)->getDstID() == dst->getId())
			{
				counter ++;
				edge = (*iter);
			}
		}
		assert(counter <= 1 && "More than 1 PDG edge between two nodes");
		return edge;
	}

	void view()
	{
		SVF::ViewGraph(this, "Data Dependency Graph");
	}
	
	void dump(const std::string &filename)
	{
		GraphPrinter::WriteGraphToFile(SVFUtil::outs(), filename, this);
	}

public:
	inline void removePDGEdge(PDGEdge *edge)
	{
		edge->getDstNode()->removeIncomingEdge(edge);
		edge->getSrcNode()->removeOutgoingEdge(edge);
		delete edge;
	}

	inline void removePDGNode(PDGNode *node)
	{
		std::set<PDGEdge *> temp;
		for (PDGEdge *e: node->getInEdges())
			temp.insert(e);
		for (PDGEdge *e: node->getOutEdges())
			temp.insert(e);
		for (PDGEdge *e: temp)
			removePDGEdge(e);
		removeGNode(node);
	}

	inline bool removePDGNode(NodeID id)
	{
		if (hasPDGNode(id))
		{
			removePDGNode(getPDGNode(id));
			return true;
		}
		return false;
	}

	inline bool addPDGEdge(PDGEdge *edge)
	{
		bool added1 = edge->getDstNode()->addIncomingEdge(edge);
		bool added2 = edge->getSrcNode()->addOutgoingEdge(edge);
		assert(added1 && added2 && "edge not added??");
		incEdgeNum();
		return added1 && added2;
	}

	virtual inline void addPDGNode(PDGNode *node, bool isSyscall)
	{
		_cluster[node->getLineNo()].insert(node->getId());
		if (_cluster_has_syscall.find(node->getLineNo()) == _cluster_has_syscall.end())
		{
			_cluster_has_syscall[node->getLineNo()] = false;
		}
		if (isSyscall)
		{
			_cluster_has_syscall[node->getLineNo()] = isSyscall;
		}
		addGNode(node->getId(), node);
	}

	const inline NodeClusterTy &getNodeCluster(int line)
	{
		return _cluster[line];
	}

	const inline bool clusterHasSyscall(int line)
	{
		return _cluster_has_syscall[line];
	}
};

template<>
struct GenericGraphTraits<SVF::PDGNode *>
	: public GenericGraphTraits<SVF::GenericNode<SVF::PDGNode, SVF::PDGEdge> *>
{
};

template<>
struct GenericGraphTraits<Inverse<SVF::PDGNode *> >
	: public GenericGraphTraits<Inverse<SVF::GenericNode<SVF::PDGNode, SVF::PDGEdge> *> >
{
};

template<>
struct GenericGraphTraits<SVF::PDG *>
	: public GenericGraphTraits<SVF::GenericGraph<SVF::PDGNode, SVF::PDGEdge> *>
{
	typedef SVF::PDGNode *NodeRef;
};

template<>
struct DOTGraphTraits<SVF::PDG *> : public DefaultDOTGraphTraits
{
	typedef PDGNode NodeType;
	typedef NodeType::iterator ChildIteratorType;

	DOTGraphTraits(bool isSimple = false) :
		DefaultDOTGraphTraits(isSimple)
	{
	}

	static std::string getGraphName(PDG *)
	{
		return "Program Dependency Graph";
	}

	static std::string getNodeLabel(PDGNode *node, PDG *)
	{
		return node->toString() + " [" + std::to_string(node->getLineNo()) + "]";
	}

	static std::string getNodeAttributes(PDGNode *node, PDG *)
	{
		return std::string("color=\"") + node->getColor() + "\"";
	}

	template<class EdgeIter>
	static std::string getEdgeAttributes(PDGNode *, EdgeIter EI, PDG *)
	{
		PDGEdge *edge = *(EI.getCurrent());
		assert(edge && "No edge found!!");

		if (SVFUtil::isa<PDGControlEdge>(edge))
		{
			return "style=solid,color=blue";
		}
		else if (SVFUtil::isa<PDGDataEdge>(edge))
		{
			return "style=dashed,color=black";
		}
		return "";
	}

	template<class EdgeIter>
	static std::string getEdgeSourceLabel(PDGNode *, EdgeIter EI)
	{
		PDGEdge *edge = *(EI.getCurrent());
		assert(edge && "No edge found!!");
		return "";
	}
};

} // end namespace SVF

#endif
