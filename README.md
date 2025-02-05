# CYB-2311 Lab 2: One-Time Pad Cryptanalysis

## Table of Contents
1. [Overview](#overview)
2. [The Story: A Cryptographic Cookie Caper](#the-story-a-cryptographic-cookie-caper)
3. [Understanding One-Time Pad](#understanding-one-time-pad)
4. [Why Key Reuse Breaks Security](#why-key-reuse-breaks-security)
5. [Your Assignment](#your-assignment)
6. [Detailed Decryption Guide](#detailed-decryption-guide)
7. [Real-World Example Walkthrough](#real-world-example-walkthrough)
8. [Advanced Techniques](#advanced-techniques)
9. [Submission Requirements](#submission-requirements)

## Overview
In this lab, you'll learn why the "one-time" in One-Time Pad is crucial by breaking multiple messages encrypted with the same key. This hands-on experience will demonstrate one of cryptography's fundamental principles: never reuse encryption keys.

## The Story: A Cryptographic Cookie Caper
Imagine this scenario: Charlie has a famous chocolate chip cookie recipe that he wants to share securely with Bob. They decide to use a one-time pad for encryption, but they make a critical mistake - they reuse the same key for multiple messages. An eavesdropper named Alice intercepts their communications. Even though Alice doesn't know the key, the key reuse gives her everything she needs to decrypt their messages.

This story illustrates exactly what you'll be doing in this lab. You're in Alice's position, with multiple intercepted messages that all used the same key.

## Understanding One-Time Pad
The one-time pad works by XORing each character of the message with a key:
- Encryption: Ciphertext = Plaintext ⊕ Key
- Decryption: Plaintext = Ciphertext ⊕ Key

Properties that make this normally secure:
1. The key is truly random
2. The key is as long as the message
3. Most importantly: The key is never reused

## Why Key Reuse Breaks Security

### The Mathematics Behind the Break
When two messages are encrypted with the same key:
```
C1 = P1 ⊕ K  (First ciphertext)
C2 = P2 ⊕ K  (Second ciphertext)

If we XOR these ciphertexts:
C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2
```

The key cancels out completely! Now we're just working with the XOR of two plaintext messages.

### Understanding ASCII XOR Patterns
When working with English text, we can use ASCII patterns:

1. ASCII Letter Properties:
    - Every uppercase letter (A-Z): Starts with `01` in binary
    - Every lowercase letter (a-z): Starts with `01` in binary
    - Space character (0x20): Starts with `00` in binary

2. XOR Pattern Results:
    - Letter ⊕ Letter = Starts with `00`
    - Letter ⊕ Space = Starts with `01`
    - Space ⊕ Space = Starts with `00`

## Your Assignment
You have 7 ciphertexts:
```
BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E

BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E

A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E

A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F

BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E

A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E

BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E
```

Each is a proper English sentence, 31 characters long.

## Detailed Decryption Guide

### Step 1: Initial Analysis
Start by XORing pairs of ciphertexts. For each position in the XORed result:
- If it starts with `00`: Both characters are the same type (both letters or both spaces)
- If it starts with `01`: One is a letter and one is a space

Example of what you might see:
```
XOR Result: 00 01 00 00 01 00 00...
            ^  ^  ^  ^  ^  ^  ^
            |  |  |  |  |  |  |
            LL LS LL LL LS LL LL  (L=letter, S=space)
```

### Step 2: Finding Word Boundaries
Look for patterns that suggest word breaks. In English text:
1. Words are separated by single spaces
2. Most words are 2-8 characters long
3. Articles ("a", "the", "an") are common at sentence starts

Example Pattern Analysis:
```
If you see:  00 00 01 01 00 01...
It might be: T  h  e  _  q  u  i  c  k...
             H  e  _  i  s  _  ...
            (where _ is a space)
```

### Step 3: Making Educated Guesses
Just like in our cookie recipe example, try guessing common phrases:

1. Start with sentence beginnings:
    - "The"
    - "A "
    - "It "
    - "This"

2. Common short words:
    - "is"
    - "are"
    - "was"
    - "the"

3. Sentence endings:
    - " is."
    - " now."
    - " too."

4. Try each possibility:
```
If first word is "the":
- XOR "the" with ciphertext
- Apply resulting key bits to other messages
- Check if results look like English
```

### Step 4: Building on Success
When you find a correct word:
1. It reveals part of the key (by XORing with ciphertext)
2. That key portion works for ALL messages
3. Look at what it reveals in other messages
4. Use context to guess surrounding words

Example of building on success:
```
Found: "the"
Key bits: 54 48 45
Applying to other messages reveals:
Message 1: "the qu..."
Message 2: "the se..."
Message 3: "the mo..."
```

## Real-World Example Walkthrough
Let's look at how we might crack the cookie recipe message:

1. First attempt - looking for spaces:
```
XOR of two messages shows:
01 pattern at positions 4, 8, 13, 17...
This suggests word lengths matching English!
```

2. Guessing common content:
```
Try "secret recipe" - it's likely in a cookie-related message
If found, XOR it with ciphertext to get key bits
Use those bits to decode other positions
```

3. Building the message:
```
Found: "secret recipe"
Context suggests: "the secret recipe"
Further context: "send the secret recipe"
Final message might be about cookies!
```

## Advanced Techniques

### Frequency Analysis
English language has predictable patterns:
1. Most common letters: e, t, a, ...
2. Most common bigrams: th, he, in, er
3. Most common trigrams: the, and, ing

### Pattern Matching
Look for repeated sequences in XOR results:
1. Same word used multiple times
2. Common phrase patterns
3. Punctuation patterns

### Verification Techniques
For each guess:
1. XOR it with the ciphertext to get key bits
2. Apply those key bits to other messages
3. Check if results contain readable English
4. Use context to verify reasonableness

**ASCII Table Reference**: [ASCII Conversion Chart](https://web.alfredstate.edu/faculty/weimandn/miscellaneous/ascii/ascii_index.html)


This reference provides:
- Full decimal/binary/hex conversions
- Character patterns and ranges
- Easy lookup for encryption/decryption work

**An Interesting Article**: [Breaking the One-Time Pad](https://medium.com/@allyson.english/perfect-secrecy-the-one-time-pad-4ce82b0b1a64)

## Submission Requirements
1. All seven decrypted messages
2. Detailed explanation of your process:
    - Initial patterns you noticed
    - How you made your first breakthrough
    - How you built on early successes
3. Description of any interesting patterns or relationships between the messages

Remember: This is like solving a puzzle. Each correct guess gives you more information to work with. Be patient, systematic, and use every small success to build toward the complete solution.

Take your time, verify your work, and don't get discouraged if your first attempts don't succeed. Even incorrect guesses can provide valuable information about what patterns to look for next.



