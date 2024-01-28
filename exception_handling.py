try:
    # Code that might raise an exception
    pass
except ValueError as ve:
    print(f"A ValueError occurred: {ve}")
except TypeError as te:
    print(f"A TypeError occurred: {te}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
