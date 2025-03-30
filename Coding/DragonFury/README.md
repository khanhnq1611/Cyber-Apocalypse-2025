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

## How to solve
In this challenge, you need to:

Read a list of subarrays, where each subarray contains possible damage values for one round of dragon attacks

Read a target damage value T

Find exactly one number from each subarray so that their sum equals T

Return this combination as a list

The challenge guarantees there's exactly one valid solution.

Systematic Search with Pruning: The problem requires finding exactly one value from each subarray to sum to a target. Backtracking allows us to:
```
Explore all possible combinations by making choices one subarray at a time
Abandon dead-end paths quickly (though this solution doesn't include explicit pruning)
Find the guaranteed unique solution without needing to check all combinations
Decision Tree Approach: The solution builds a decision tree where:

Each level corresponds to a subarray
Each branch represents selecting a specific value from that subarray
A complete path from root to leaf represents one possible combination
Early Termination: The found flag allows the algorithm to stop once the solution is found, which is more efficient than generating all possible combinations.
```
## Result

![image](https://github.com/user-attachments/assets/ad489185-59b2-4781-96ca-610405e7a729)
