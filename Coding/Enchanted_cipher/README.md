## Challenge overview

```
The Grand Arcane Codex has been corrupted, altering historical records. Each entry has been encoded with an enchanted shifting cipher that encrypts a plaintext composed of 3–7 randomly generated words.

The cipher operates as follows:

Alphabetical characters are processed in groups of 5 (ignoring non-alphabetical characters).
For each group, a random shift between 1 and 25 is chosen and applied to every letter in that group.
After the encoded message, an additional line indicates the total number of shift groups, followed by another line listing the random shift values used for each group.
Your quest is to decode the given input and restore the original plaintext.

Example
Input:

ibeqtsl
2
[4, 7]

Output:
example

```
## Problem Understanding
The challenge involves decoding an encrypted message that has been encoded using a shifting cipher. The cipher operates as follows:

* **Alphabetical Characters Only:** Non-alphabetical characters are ignored during encryption and decryption. Their positions in the original string are preserved.
* **Grouping:** Alphabetical characters are grouped into chunks of 5. Each group is shifted by a specific value (provided in the input).
* **Shifting:** Each letter in a group is shifted backward by the corresponding shift value to decode it. Shifting is circular, meaning after 'a', it wraps back to 'z' (and similarly for uppercase letters).

The goal is to reverse the encryption process and reconstruct the original plaintext while preserving the positions of non-alphabetical characters.

## Key Concepts to Solve the Challenge

* **Extract Alphabetical Characters:**
    * Separate the alphabetical characters from the input string while keeping track of their original positions.
    * This ensures that non-alphabetical characters can be reinserted into their original positions after decryption.
* **Group Characters:**
    * Divide the extracted alphabetical characters into groups of 5.
    * If the last group has fewer than 5 characters, it remains as is.
* **Apply Reverse Shifting:**
    * For each group, use the corresponding shift value (provided in the input) to reverse the encryption:
        * Handle both uppercase and lowercase letters separately to maintain their case.
        * Use modular arithmetic to ensure circular shifting within the alphabet.
* **Reconstruct the Original String:**
    * Replace the decrypted alphabetical characters back into their original positions in the string.
    * Non-alphabetical characters remain unchanged.
* **Output the Result:**
    * Combine the characters into a single string and print the decoded plaintext.

## Steps to Write the Code

**Step 1: Parse the Input**
* Read the encrypted string, the number of groups (N), and the list of shift values.
* Convert the shift values from a string representation (e.g., `"[4, 7]"` ) into a Python list of integers.

**Step 2: Extract Alphabetical Characters**
* Iterate through the encrypted string.
* Collect all alphabetical characters into a list (e.g., `letters`).
* Record their original positions in a separate list (e.g., `positions`).

**Step 3: Group the Characters**
* Divide the `letters` list into groups of 5.
* Store these groups in a list (e.g., `groups`).

**Step 4: Decrypt Each Group**
* For each group, use the corresponding shift value to reverse the encryption:
    * For lowercase letters, calculate the new character using the ASCII value of `'a'` as the base.
    * For uppercase letters, use the ASCII value of `'A'` as the base.
    * Apply the reverse shift using modular arithmetic: `(offset - shift) % 26`.

**Step 5: Reconstruct the Original String**
* Create a mutable list from the encrypted string.
* Replace the characters at the recorded positions with the decrypted letters.
* Leave non-alphabetical characters unchanged.

**Step 6: Output the Result**
* Join the reconstructed list into a single string and print it.

## Result
![image](https://github.com/user-attachments/assets/cfd0aa07-eb1d-4e51-9e18-d7a31121956c)

