# Input the text as a single string
input_text = input()  # Example: "[3, 2, 5, 10, 7]"

# Convert input string to a list of integers
tokens = eval(input_text)

# Function to find the maximum sum of non-adjacent numbers
def max_non_adjacent_sum(arr):
    if not arr:
        return 0
    if len(arr) == 1:
        return arr[0]
    
    prev2 = 0
    prev1 = arr[0]
    
    for i in range(1, len(arr)):
        current = max(prev1, prev2 + arr[i])
        prev2 = prev1
        prev1 = current
    
    return prev1

# Compute the result and print
print(max_non_adjacent_sum(tokens))
