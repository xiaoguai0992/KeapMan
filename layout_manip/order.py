from collections import defaultdict, deque

class ConstraintSolver:
    class UnionFind:
        def __init__(self):
            self.parent = {}

        def find(self, x):
            if x != self.parent.setdefault(x, x):
                self.parent[x] = self.find(self.parent[x])
            return self.parent[x]

        def union(self, x, y):
            self.parent[self.find(x)] = self.find(y)

    def __init__(self):
        pass

    def parse_constraints(self, constraints):
        self.uf = self.UnionFind()
        self.graph = defaultdict(list)
        self.indegree = defaultdict(int)
        # Step 1: First pass — only handle overlap
        for constraint in constraints:
            if constraint.startswith("overlap("):
                x, y = map(int, constraint[8:-1].split(","))
                self.uf.union(x, y)

        # Step 2: Second pass — handle adjacent with conflict check
        self.graph_parent = {}
        for constraint in constraints:
            if constraint.startswith("adjacent("):
                x, y = map(int, constraint[9:-1].split(","))
                x_root = self.uf.find(x)
                y_root = self.uf.find(y)
                if x_root == y_root:
                    raise ValueError(f"Conflict: {x} and {y} overlap but also adjacent")
                self.graph[x_root].append(y_root)
                self.indegree[y_root] += 1
                self.indegree.setdefault(x_root, 0)

        # Step 3: Topological sort to determine group positions
        queue = deque()
        location = {}
        all_roots = set(self.uf.find(x) for x in self.uf.parent)
        print(f"all_roots:{all_roots}")
        for node in all_roots:
            if self.indegree[node] == 0:
                queue.append(node)
                location[node] = 0

        current_pos = 0
        #print(f"queue {queue}")
        for u in queue:
            node = u
            while True:
                location[node] = current_pos
                #print(f"node{node} at {current_pos}")
                current_pos += 1
                if node not in self.graph or len(self.graph[node]) == 0:
                    break
                node = self.graph[node][0]

        '''
        while queue:
            node = queue.popleft()
            for neighbor in self.graph[node]:
                location[neighbor] = max(location.get(neighbor, 0), location[node] + 1)
                self.indegree[neighbor] -= 1
                if self.indegree[neighbor] == 0:
                    queue.append(neighbor)
        '''

        # Step 4: Assign final location to each original object
        result = {}
        for x in self.uf.parent:
            group = self.uf.find(x)
            result[x] = location[group]
        
        return result

if __name__ == '__main__':
    order_solver = ConstraintSolver()
    constraints = [
        "adjacent(1, 2)",
        "adjacent(2, 3)",
        "adjacent(4, 5)",
        "adjacent(5, 6)",
    ]
    positions = order_solver.parse_constraints(constraints)
    print(positions)
