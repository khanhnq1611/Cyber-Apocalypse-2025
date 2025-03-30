import ast

def find_combination(subarrays, T):
    path = []
    found = False

    def backtrack(index, current_sum, current_path):
        nonlocal found
        if found:
            return
        if index == len(subarrays):
            if current_sum == T:
                nonlocal path
                path = current_path.copy()
                found = True
            return
        for num in subarrays[index]:
            backtrack(index + 1, current_sum + num, current_path + [num])

    backtrack(0, 0, [])
    return path

# Read input
subarrays_str = input().strip()
subarrays = ast.literal_eval(subarrays_str)
T = int(input())

result = find_combination(subarrays, T)
print(result)
