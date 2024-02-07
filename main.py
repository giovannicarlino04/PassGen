import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import random
import string

def generate_password(length=12, uppercase=True, digits=True, special_characters=True):
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase if uppercase else ''
    numeric_digits = string.digits if digits else ''
    special_chars = string.punctuation if special_characters else ''

    all_characters = lowercase_letters + uppercase_letters + numeric_digits + special_chars

    length = max(length, 4)
    
    password = ''.join(random.choice(all_characters) for _ in range(length))

    return password

def generate_password_button_click():
    length = int(length_var.get())
    uppercase = uppercase_var.get()
    digits = digits_var.get()
    special_characters = special_characters_var.get()

    password = generate_password(length, uppercase, digits, special_characters)
    result_var.set(password)

def copy_to_clipboard():
    password = result_var.get()
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# Create the main window
root = tk.Tk()
root.title("Password Generator")

# Create and configure the main frame
main_frame = ttk.Frame(root, padding="20")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Widgets
length_var = tk.StringVar(value="12")
uppercase_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
special_characters_var = tk.BooleanVar(value=True)
result_var = tk.StringVar()

length_label = ttk.Label(main_frame, text="Password Length:")
length_entry = ttk.Entry(main_frame, textvariable=length_var, width=5)
uppercase_checkbox = ttk.Checkbutton(main_frame, text="Include Uppercase", variable=uppercase_var)
digits_checkbox = ttk.Checkbutton(main_frame, text="Include Digits", variable=digits_var)
special_characters_checkbox = ttk.Checkbutton(main_frame, text="Include Special Characters", variable=special_characters_var)
generate_button = ttk.Button(main_frame, text="Generate Password", command=generate_password_button_click)
result_label = ttk.Label(main_frame, text="Generated Password:")
result_entry = ttk.Entry(main_frame, textvariable=result_var, state="readonly")
copy_button = ttk.Button(main_frame, text="Copy to Clipboard", command=copy_to_clipboard)

# Layout
length_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
length_entry.grid(row=0, column=1, sticky=tk.W, pady=(0, 10))
uppercase_checkbox.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
digits_checkbox.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
special_characters_checkbox.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
generate_button.grid(row=4, column=0, columnspan=2, pady=(10, 10))
result_label.grid(row=5, column=0, columnspan=2, pady=(10, 0))
result_entry.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
copy_button.grid(row=7, column=0, columnspan=2)

# Run the application
root.mainloop()
