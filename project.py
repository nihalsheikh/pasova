from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Optional, Any

import csv
import os
import random
import secrets
import string


DATETIME_FORMAT = "%d-%m-%Y %H:%M:%S"  # DD-MM-YYYY HH:MM:SS


def main():
	password = generate_password()
	print(f"Password generated: {password}")


# Get the User required password length
def get_password_length() -> int:
	# Get Password length and check its type
	while True:
		try:
			password_length = int(input("Enter password length (min. length >= 8): "))

			if password_length >= 8:
				return password_length
			else:
				print("Minimum Password Length must be 8. Please try again.")
		except ValueError:
			print("Invalid input. Please enter a valid password length (≥ 8).")

# Generate password with Uppercase, Lowercase, Numbers (0-9), Symbols (!, @, #, $, etc...)
def generate_password() -> str:
	length = get_password_length()

	# Generate Password Logic goes here
	# Define characters to be used in the password
	lowercase_chars = string.ascii_lowercase
	uppercase_chars = string.ascii_uppercase
	numbers = string.digits
	symbols = string.punctuation

	all_chars = lowercase_chars + uppercase_chars + numbers + symbols

	# What is password going to include and what if error occurs while generating it
	try:
		password = [
			secrets.choice(lowercase_chars),
			secrets.choice(uppercase_chars),
			secrets.choice(numbers),
			secrets.choice(symbols)
		]
	except IndexError:
		print("ERROR Generating Password. Minimum required password length is 8")
		return ""

	# calc how much more chars needed to be added in the password
	remaining_length = length - len(password)

	# Add remaining chars in password
	for _ in range(remaining_length):
		password.append(secrets.choice(all_chars))

	# make sure to generate a random password every time
	secure_random = secrets.SystemRandom()
	secure_random.shuffle(password)

	# return the generated password string back to user
	return "".join(password)


# check current time for account data
def _now_str() -> str:
    return datetime.now().strftime(DATETIME_FORMAT)

# Check name for account data
def _validate_string(name: str, value: Any, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} field must be a name.")
    if not allow_empty and value.strip() == "":
        raise ValueError(f"{name} field cannot be empty.")
    return value.strip()

# check url for account data
def _validate_url(url: str) -> str:
    url = _validate_string("URL", url)
    parsed = urlparse(url)
    # allow URLs like https://example.com
    if parsed.scheme and parsed.netloc:
        return url
    # if user inputs 'example.com' allow it but change it to "http://example.com"
    if "." in url and " " not in url:
        return "http://" + url
    raise ValueError("Invalid URL. Please provide full URL (ex: https://example.com)")

# Add data to file
def add_account_data(url: str, username: str, password: str, notes: str = "") -> Dict[str, str]:
	url = _validate_url(url)
	username = _validate_string("Username", username)
	password = _validate_string("Password", password)
	notes = _validate_string("Notes", notes, allow_empty=True)

	now = _now_str()

	entry = {
			"URL": url,
			"Username": username,
			"Password": password,
			"Label": notes,
			"CreatedAt": now,
			"UpdatedAt": f"{now} — created"
	}
	return entry

# Update data in file
def update_account_data(entry: Dict[str, str], url: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, notes: Optional[str] = None) -> Dict[str, str]:
    if not isinstance(entry, dict):
        raise TypeError("entry must be a dict created by add_account_data().")

    allowed_keys = {"URL", "Username", "Password", "Label", "CreatedAt", "UpdatedAt"}
    if not allowed_keys.issuperset(entry.keys()):
        raise ValueError("entry dict does not have the expected structure.")

    changes = []

    if url is not None: # check url change
        new_url = _validate_url(url)
        if new_url != entry.get("URL"):
            entry["URL"] = new_url
            changes.append("URL")

    if username is not None: # check username change (email or username)
        new_user = _validate_string("Username", username)
        if new_user != entry.get("Username"):
            entry["Username"] = new_user
            changes.append("Username")

    if password is not None: # check password changes
        new_pw = _validate_string("Password", password)
        if new_pw != entry.get("Password"):
            entry["Password"] = new_pw
            changes.append("Password")

    if notes is not None: # check notes changes
        new_notes = _validate_string("Notes", notes, allow_empty=True)
        if new_notes != entry.get("Label"):
            entry["Label"] = new_notes
            changes.append("Label")

    if not changes: # when no changes made
        raise ValueError("No changes detected — provide at least one different field to update.")

    now = _now_str()

	# Date & Time with updated fields
    entry["UpdatedAt"] = f"{now} — updated: {', '.join(changes)}"

    return entry

	
def save_passwords_to_csv():
	...


if __name__ == "__main__":
	main()
