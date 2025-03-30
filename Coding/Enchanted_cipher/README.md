## Challenge overview

In this challenge, you are given an encoded message produced by an enchanted shifting cipher. The original plaintext consists of 3–7 randomly generated words, and the encryption process involves the following steps:

- **Grouping Characters:**  
  The plaintext is stripped of spaces and punctuation, and its alphabetical characters are grouped into segments of 5.
  
- **Shifting Letters:**  
  For each group, every letter is shifted by a random value between 1 and 25 (similar to a Caesar cipher). When a group ends, a new random shift is applied to the next group of 5 characters.
  
After the encoded message, two additional lines are provided:
1. The total number of shift groups applied.
2. A list of the random shift values used for each group.

**Your Task:**  
You must decode the encoded message by reversing the shifting process and restoring the original plaintext.



