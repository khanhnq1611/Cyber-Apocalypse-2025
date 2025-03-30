## Challenge overview
```
In the mystical realm of the Floating Isles, ancient dragons traverse the skies between floating sanctuaries.
However, unpredictable winds now pose a dynamic threat!

As a Dragon Flight Master, your mission is to:

Handle both sudden wind changes and challenging flight path queries.
Process update operations that modify the wind effect on any flight segment.
Compute the maximum favorable continuous flight stretch (i.e., the maximum contiguous subarray sum) within a specified range.
Your precise calculations are critical to determine the safest and most efficient route for the dragons.
Adapt quickly as wind conditions change, ensuring their journey remains uninterrupted.

Input Format Explanation
The input provided to the challenge is structured as follows:

First Line: Two space-separated integers, N and Q.
N represents the number of flight segments.
Q represents the number of operations to perform.
Second Line: N space-separated integers representing the initial net wind effects for each flight segment.
A positive value indicates a tailwind, which helps the dragon travel further.
A negative value indicates a headwind, which reduces the effective flight distance.
Next Q Lines: Each of these lines represents an operation that can be one of the following:
U i x: An update operation where the wind effect on the i-th segment is changed to x.
Q l r: A query operation requesting the maximum contiguous subarray sum (i.e., the maximum net flight distance) for the segments
in the range from l to r (inclusive).
Flight Example
Flight Path Input
5 3 10 -2 3 -1 5 Q 1 5 U 2 4 Q 1 3
Expected Output
15 17
```
## **Key Concept & Main Idea**
### ** Segment Tree **
- **Efficient for dynamic updates & queries**.
- **Handles both operations in O(log N)**, making it **scalable** for large inputs.

This challenge revolves around efficiently handling **range queries** and **point updates** on an array of wind effects. The main challenge is that we need to perform **two types of operations** efficiently:

1. **Update Operation (`U i x`)**:
   - Modify the wind effect at index `i` to `x`.

2. **Query Operation (`Q l r`)**:
   - Find the **maximum contiguous subarray sum** (Kadane’s Algorithm) in the given range `[l, r]`.

Since direct computations for each query (using brute force) would be too slow, we need a **Segment Tree** to handle **dynamic updates** and **range queries** in **O(log N)** time.

---

## **Step-by-Step Breakdown to Solve the Problem**

### **1. Choosing the Right Data Structure**
Since we need:
- **Efficient range queries** (Kadane's maximum subarray sum for a given range).
- **Efficient point updates** (modifying a single wind effect).

A **Segment Tree** is the perfect choice because:
- It allows **fast updates (`O(log N)`)**.
- It enables **fast range queries (`O(log N)`)**.

Each node in our segment tree will store **four key values**:
- **`sum`** → Total sum of elements in the range.
- **`prefix_max`** → Maximum subarray sum starting from the leftmost element.
- **`suffix_max`** → Maximum subarray sum ending at the rightmost element.
- **`best_max`** → Maximum contiguous subarray sum in the entire range (Kadane’s value).

### **2. Building the Segment Tree**
- Start from the **bottom** (leaf nodes).
- Each **leaf** corresponds to a single element from the input array.
- Each **internal node** is built by merging two child nodes.

### **3. Merging Two Nodes**
For two segments (`left` and `right`), we compute:
- **Total Sum** → `left.sum + right.sum`
- **Prefix Max** → `max(left.prefix_max, left.sum + right.prefix_max)`
- **Suffix Max** → `max(right.suffix_max, right.sum + left.suffix_max)`
- **Best Max** → `max(left.best_max, right.best_max, left.suffix_max + right.prefix_max)`

### **4. Performing an Update Operation (`U i x`)**
- Locate the **specific index** in the segment tree.
- Replace its value with `x`.
- Recalculate affected nodes up to the root.

### **5. Performing a Query Operation (`Q l r`)**
- Recursively compute the result for subranges within `[l, r]`.
- Merge results from left and right children.

---

## **Code Breakdown (Step-by-Step)**

### **Step 1: Define the Segment Tree Node**
Each node must store:
- `sum` → Total sum of elements in the range.
- `prefix_max` → Best sum starting from the left.
- `suffix_max` → Best sum ending at the right.
- `best_max` → Best sum anywhere in the range.

```python
class SegmentTree:
    class Node:
        def __init__(self, sum_val=0, prefix_max=0, suffix_max=0, best_max=0):
            self.sum = sum_val
            self.prefix_max = prefix_max
            self.suffix_max = suffix_max
            self.best_max = best_max
```

---

### **Step 2: Build the Segment Tree**
- Recursively construct the tree from the input array.

```python
    def __init__(self, arr):
        self.n = len(arr)
        self.tree = [self.Node() for _ in range(4 * self.n)]  # Large enough tree
        self.build(arr, 0, 0, self.n - 1)

    def build(self, arr, node, start, end):
        if start == end:  # Leaf node
            val = arr[start]
            self.tree[node] = self.Node(val, val, val, val)
            return
        mid = (start + end) // 2
        left_child = 2 * node + 1
        right_child = 2 * node + 2
        self.build(arr, left_child, start, mid)
        self.build(arr, right_child, mid + 1, end)
        self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])
```

---

### **Step 3: Merge Two Nodes**
This function helps combine results from two segments.

```python
    def merge(self, left, right):
        total_sum = left.sum + right.sum
        prefix_max = max(left.prefix_max, left.sum + right.prefix_max)
        suffix_max = max(right.suffix_max, right.sum + left.suffix_max)
        best_max = max(left.best_max, right.best_max, left.suffix_max + right.prefix_max)
        return self.Node(total_sum, prefix_max, suffix_max, best_max)
```

---

### **Step 4: Handle Updates (`U i x`)**
- Modify a **single index** in the segment tree.
- Update affected parent nodes.

```python
    def update(self, idx, value, node=0, start=0, end=None):
        if end is None:
            end = self.n - 1
        if start == end:  # Leaf node
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
```

---

### **Step 5: Handle Queries (`Q l r`)**
- Find the **maximum contiguous subarray sum** in a given range.

```python
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
```

---

### **Step 6: Read Input and Process Commands**
```python
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
```

---


## Result
![image](https://github.com/user-attachments/assets/9264f6b1-29fe-40d1-9262-03b46ecdb9f9)
