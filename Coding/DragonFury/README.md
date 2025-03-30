## Challenge
```
In the epic battle against Malakar's dark forces, the ancient dragons must unleash a series of precise attacks.
Each attack round offers several potential damage values—but only one combination of attacks will
sum up exactly to the damage required to vanquish the enemy.

Your Task
Read a single string that represents a list of subarrays. Each subarray contains possible damage values for one round.

Example:
[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
Read an integer T that represents the target total damage required.
Pick exactly one number from each subarray so that their sum equals T.
It is guaranteed that there is exactly one valid solution.
Output the valid combination (as a list) that meets the target damage.

Example
 Input
[[13, 15, 27, 17], [24, 15, 28, 6, 15, 16], [7, 25, 10, 14, 11], [23, 30, 14, 10]]
77
 Output
[23, 30, 14, 10]
 Explanation:

The input represents 4 rounds of attacks, each with a list of possible damage values. The unique valid solution is the combination
[23, 30, 14, 10]
which sums exactly to 77.
```

#### Key Concepts - Backtracking
```
Backtracking is a recursive algorithm used to explore all possible combinations or paths in a problem.
It allows you to "try" a solution, and if it doesn't work, "backtrack" to try another option.
Recursive Exploration:
For each subarray, try every number and move to the next subarray.
Keep track of the current sum and the selected numbers (path).
Early Termination:
Since there is exactly one valid solution, stop the recursion as soon as the solution is found.
```
#### Plan the Solution
```
Input Parsing:
Read the input string and convert it into a list of subarrays.
Read the target value T.
Recursive Function:
Create a recursive function to explore all combinations of numbers.
Pass the current index, current sum, and the current path (selected numbers) as parameters.
Base Case:
If all subarrays are processed (index == len(subarrays)):
Check if the current sum equals T.
If yes, save the current path as the solution and stop further exploration.
Recursive Case:
For each number in the current subarray:
Add the number to the current sum and path.
Recursively call the function for the next subarray.
Output:
Return the valid combination once found.
```
## Result

![image](https://github.com/user-attachments/assets/ad489185-59b2-4781-96ca-610405e7a729)
