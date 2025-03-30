encrypted = input().strip()
N = int(input().strip())
shifts_line = input().strip()
shifts = list(map(int, shifts_line.strip('[]').split(',')))

# Extract letters and non-letters
letters = []
positions = []  # To track where letters are in the original string
for i, c in enumerate(encrypted):
    if c.isalpha():
        letters.append(c)
        positions.append(i)

# Split letters into groups of 5
groups = []
for i in range(0, len(letters), 5):
    groups.append(letters[i:i+5])

# Decrypt each group
decrypted_letters = []
for i in range(N):
    shift = shifts[i]
    group = groups[i]
    for c in group:
        if c.islower():
            base = ord('a')
        else:
            base = ord('A')
        offset = ord(c) - base
        new_offset = (offset - shift) % 26
        new_char = chr(base + new_offset)
        decrypted_letters.append(new_char)

# Reconstruct the result
result = list(encrypted)
dl_idx = 0
for pos in positions:
    result[pos] = decrypted_letters[dl_idx]
    dl_idx += 1

print(''.join(result))
