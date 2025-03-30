# Input the text as a single string
input_text = input()  # This should be the grid representation as a string

# Parse the grid from the input
import json
import ast

try:
    # Try to parse using json
    grid = json.loads(input_text)
except:
    try:
        # Try to parse using ast.literal_eval
        grid = ast.literal_eval(input_text)
    except:
        # Fallback to manual parsing if needed
        grid = []
        rows = input_text.strip('[]').split('], [')
        for row in rows:
            grid_row = []
            elements = row.strip('[]').split(', ')
            for elem in elements:
                if elem.strip("'\"") == 'E':
                    grid_row.append('E')
                else:
                    grid_row.append(int(elem))
            grid.append(grid_row)

# Use BFS to find the shortest path
from collections import deque

def find_shortest_path(grid):
    rows = len(grid)
    cols = len(grid[0])
    
    # Find the exit position
    exit_position = None
    for i in range(rows):
        for j in range(cols):
            if grid[i][j] == 'E':
                exit_position = (i, j)
                break
        if exit_position:
            break
    
    # If exit not found
    if not exit_position:
        return -1
    
    # Define the possible moves (up, right, down, left)
    directions = [(-1, 0), (0, 1), (1, 0), (0, -1)]
    
    # Use BFS to find the shortest path
    queue = deque([(0, 0, 0)])  # (row, col, steps)
    visited = set([(0, 0)])
    
    while queue:
        row, col, steps = queue.popleft()
        
        # Check if we reached the exit
        if (row, col) == exit_position:
            return steps
        
        # Try all four directions
        for dr, dc in directions:
            new_row, new_col = row + dr, col + dc
            
            # Check if the new position is valid
            if (0 <= new_row < rows and 
                0 <= new_col < cols and 
                (new_row, new_col) not in visited and 
                grid[new_row][new_col] != 1):
                
                queue.append((new_row, new_col, steps + 1))
                visited.add((new_row, new_col))
    
    # If there is no path to the exit
    return -1

# Find the shortest path and print the result
shortest_path = find_shortest_path(grid)
print(shortest_path)


