import re

def sanitize_string(input_string):
    # Remove leading/trailing whitespaces
    sanitized_input = input_string.strip()
    # Replace special characters or escape sequences
    sanitized_input = sanitized_input.replace("<", "<").replace(">", ">")
    return sanitized_input

def sanitize_integer(input_integer):
    # Ensure the input is an integer
    try:
        sanitized_input = int(input_integer)
    except ValueError:
        raise ValueError("Input is not an integer")
    return sanitized_input

def sanitize_email(input_email):
    # Validate the email using a simple regex
    if not re.match(r"[^@]+@[^@]+\.[^@]+", input_email):
        raise ValueError("Input is not a valid email address")
    return input_email
