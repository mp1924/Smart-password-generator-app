import secrets
import string

print("Smart Password Generator")

length = int(input("Enter password length: "))

use_upper = input("Include uppercase? (y/n): ").lower() == "y"
use_lower = input("Include lowercase? (y/n): ").lower() == "y"
use_numbers = input("Include numbers? (y/n): ").lower() == "y"
use_symbols = input("Include symbols? (y/n): ").lower() == "y"

char_pool = ""

if use_upper:
    char_pool += string.ascii_uppercase

if use_lower:
    char_pool += string.ascii_lowercase

if use_numbers:
    char_pool += string.digits

if use_symbols:
    char_pool += string.punctuation


if len(char_pool) == 0:
    print(" Error: No character types selected!")
    exit()

password = ""
for i in range(length):
    password += secrets.choice(char_pool)
print("\nGenerated Password:", password)

def check_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score in [3, 4]:
        return "Medium"
    else:
        return "Strong"

print("Password Strength:", check_strength(password))
