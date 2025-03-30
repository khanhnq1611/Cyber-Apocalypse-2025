class SegmentTree:
    class Node:
        def __init__(self, sum_val=0, prefix_max=0, suffix_max=0, best_max=0):
            self.sum = sum_val
            self.prefix_max = prefix_max
            self.suffix_max = suffix_max
            self.best_max = best_max

    def __init__(self, arr):
        self.n = len(arr)
        self.tree = [self.Node() for _ in range(4 * self.n)]
        self.build(arr, 0, 0, self.n - 1)

    def build(self, arr, node, start, end):
        if start == end:
            val = arr[start]
            self.tree[node] = self.Node(val, val, val, val)
            return
        mid = (start + end) // 2
        left_child = 2 * node + 1
        right_child = 2 * node + 2
        self.build(arr, left_child, start, mid)
        self.build(arr, right_child, mid + 1, end)
        self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])

    def merge(self, left, right):
        total_sum = left.sum + right.sum
        prefix_max = max(left.prefix_max, left.sum + right.prefix_max)
        suffix_max = max(right.suffix_max, right.sum + left.suffix_max)
        best_max = max(left.best_max, right.best_max, left.suffix_max + right.prefix_max)
        return self.Node(total_sum, prefix_max, suffix_max, best_max)

    def update(self, idx, value, node=0, start=0, end=None):
        if end is None:
            end = self.n - 1
        if start == end:
            self.tree[node] = self.Node(value, value, value, value)
            return
        mid = (start + end) // 2
        left_child = 2 * node + 1
        right_child = 2 * node + 2
        if idx <= mid:
            self.update(idx, value, left_child, start, mid)
        else:
            self.update(idx, value, right_child, mid + 1, end)
        self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])

    def query(self, L, R, node=0, start=0, end=None):
        if end is None:
            end = self.n - 1
        if R < start or L > end:
            return self.Node(float('-inf'), float('-inf'), float('-inf'), float('-inf'))
        if L <= start and end <= R:
            return self.tree[node]
        mid = (start + end) // 2
        left_res = self.query(L, R, 2 * node + 1, start, mid)
        right_res = self.query(L, R, 2 * node + 2, mid + 1, end)
        return self.merge(left_res, right_res)

# Read input
input1 = input()  # "N Q"
input2 = input()  # Initial wind effects

N, Q = map(int, input1.split())
arr = list(map(int, input2.split()))

# Initialize Segment Tree
st = SegmentTree(arr)

# Process queries
for _ in range(Q):
    op = input().split()
    if op[0] == 'U':
        i, x = int(op[1]) - 1, int(op[2])  # Convert to 0-based index
        st.update(i, x)
    elif op[0] == 'Q':
        l, r = int(op[1]) - 1, int(op[2]) - 1  # Convert to 0-based index
        print(st.query(l, r).best_max)
