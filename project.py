import secrets
import string


def main():
	password = generate_password()
	print(f"Password generated: {password}")



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




if __name__ == "__main__":
	main()
