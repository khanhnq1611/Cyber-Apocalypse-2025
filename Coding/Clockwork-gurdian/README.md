## Challenge
```
Write a program to compute the shortest safe path in a grid-based labyrinth Eldoria's Skywatch Spire from the starting position `(0, 0)` to the exit cell (denoted by `'E'`). The grid is composed of:

- **Safe cells:** represented by `0`
- **Hostile sentinels (obstacles):** represented by `1`
- **Exit cell:** represented by `'E'`

Movement is restricted to the four cardinal directions (up, down, left, right). If no safe path exists, the program should output `-1`.

For example, given the grid:

[
    [0, 0, 1, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 1, 1, 0, 'E']
]
```
### Problem Understanding
The challenge is to compute the shortest safe path in a grid-based labyrinth. The grid contains:
* **Safe cells (0):** You can move through these cells.
* **Hostile sentinels (1):** These are obstacles that cannot be traversed.
* **Exit cell ('E'):** The destination you need to reach.

You start at the top-left corner **(0, 0)** and can move in the four cardinal directions (up, down, left, right). The goal is to find the minimum number of steps required to reach the exit cell **'E'**. If no path exists, the output should be **-1**.

### Key Concepts to Solve the Challenge

**Breadth-First Search (BFS):**
* BFS is the ideal algorithm for finding the shortest path in an unweighted grid.
* It explores all possible moves level by level, ensuring that the first time it reaches the exit cell, it has taken the minimum number of steps.

**Grid Traversal:**
* Use a queue to keep track of the current position and the number of steps taken so far.
* Use a `visited` set to avoid revisiting cells and prevent infinite loops.

**Valid Moves:**
* Movement is restricted to the four cardinal directions (up, down, left, right).
* A move is valid if:
    * It stays within the grid boundaries.
    * It does not land on an obstacle (1).
    * It has not been visited before.

**Edge Cases:**
* The grid does not contain an exit cell `'E'`.
* The starting cell `(0, 0)` is an obstacle.
* The exit cell `'E'` is surrounded by obstacles, making it unreachable.

### Mindset to Write the Code

**Step 1: Parse the Input**
* The input is provided as a string representation of the grid.
* Use `json.loads` or `ast.literal_eval` to safely parse the input into a Python list.
* If parsing fails, manually process the string to construct the grid.

**Step 2: Locate the Exit Cell**
* Traverse the grid to find the coordinates of the exit cell `'E'`.
* If the exit cell is not found, return `-1` immediately.

**Step 3: Implement BFS for Shortest Path**
* Initialize a queue with the starting position `(0, 0)` and a step count of `0`.
* Use a `visited` set to track cells that have already been processed.
* Define the possible moves (up, down, left, right) as direction vectors.

**Step 4: Traverse the Grid**
* While the queue is not empty:
    * Dequeue the current position and step count.
    * Check if the current position is the exit cell. If yes, return the step count.
    * For each possible move:
        * Calculate the new position.
        * Check if the move is valid (within bounds, not an obstacle, not visited).
        * If valid, enqueue the new position with an incremented step count and mark it as visited.

**Step 5: Handle No Path Case**
* If the queue is exhausted and the exit cell has not been reached, return `-1`.

### Result
![image](https://github.com/user-attachments/assets/2d0a4082-bfdc-4d60-8ff6-6f0fe9bfcabc)
