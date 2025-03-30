### Challenge Overview
```
Deep within the ancient halls lies the secret of the Dragon's Heart—a power that can only be unlocked by combining magical tokens in just the right way. The tokens are delicate: if you combine two adjacent tokens, their energy dissipates into the void.

Your quest is to determine the maximum amount of energy that can be harnessed by selecting tokens such that no two selected tokens are adjacent. This challenge is equivalent to finding the maximum sum of non-adjacent numbers from a list.

🔥
Your Quest
Input Format:
 A single line containing a Python-style list of integers representing token energies.
Example: [3, 2, 5, 10, 7]
Output Format:
 A single integer that is the maximum energy obtainable by summing non-adjacent tokens.
🔥
Example 1
Input:
[3, 2, 5, 10, 7]
Output:
15
Explanation: The optimal selection is to pick tokens 3, 5, and 7 (non-adjacent), yielding a sum of 3 + 5 + 7 = 15.

🔥
Example 2
Input:
[10, 18, 4, 7]
Output:
25
Explanation: The best choice is to select 18 and 7 (tokens at positions 2 and 4) for a total of 18 + 7 = 25.
```
### Key Concept
This problem is a variation of the Dynamic Programming. 
The goal is to select numbers from a list such that no two selected numbers are adjacent while maximizing their sum.  

### Main Idea to Solve the Challenge
1. **Dynamic Programming Approach**  
   - Define `prev1` as the maximum sum **including** the previous number.  
   - Define `prev2` as the maximum sum **excluding** the previous number.  
   - Iterate through the list, updating `prev1` and `prev2` at each step.  

2. **Recurrence Relation**  
   - For each number at index `i`, decide whether to:  
     - **Include** it (`prev2 + arr[i]`), skipping the adjacent number.  
     - **Exclude** it (`prev1`), keeping the previous best sum.  
   - The transition formula is:  
     ```
     current = max(prev1, prev2 + arr[i])
     ```
   - Update `prev2 = prev1` and `prev1 = current` after each step.  

3. **Base Cases**  
   - If the list is empty, return `0`.  
   - If the list has only one element, return that element.  

4. **Time Complexity:**  
   - **O(N)**: We process each element once, making this approach efficient.

### Result
Full code in ``writeup.py``
``HTB{SUMM0N3RS_INC4NT4T10N_R3S0LV3D_7305466de02e687b23c162bcffefcd64}``

