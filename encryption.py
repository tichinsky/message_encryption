import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
import hashlib
import base64
from PIL import Image
import numpy as np

# Function to generate a key from a fixed hash
def generate_key_from_hash(hash_value):
    key = hash_value[:32].encode()
    return base64.urlsafe_b64encode(key.ljust(32, b'\0'))

# Function to convert an image to a string and generate a hash
def generate_fixed_hash_from_image(image_path):
    image = Image.open(image_path)
    gray_image = image.convert('L')
    image_array = np.array(gray_image)
    image_string = np.array2string(image_array, separator=',', threshold=np.inf)
    fixed_hash = hashlib.sha256(image_string.encode()).hexdigest()
    return fixed_hash

# Function to encrypt text
def encrypt_text():
    user_text = entry_encrypt.get()
    if user_text.strip():
        encrypted = cipher_suite.encrypt(user_text.encode()).decode()
        result_encrypt.config(state=tk.NORMAL)
        result_encrypt.delete(1.0, tk.END)
        result_encrypt.insert(tk.END, encrypted)
        result_encrypt.config(state=tk.DISABLED)
    else:
        messagebox.showwarning("Warning", "Please enter text to encrypt!")

# Function to decrypt text
def decrypt_text():
    user_text = entry_decrypt.get()
    if user_text.strip():
        try:
            decrypted = cipher_suite.decrypt(user_text.encode()).decode()
            result_decrypt.config(state=tk.NORMAL)
            result_decrypt.delete(1.0, tk.END)
            result_decrypt.insert(tk.END, decrypted)
            result_decrypt.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt text!")
    else:
        messagebox.showwarning("Warning", "Please enter text to decrypt!")

# Function to copy encrypted text to clipboard
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_encrypt.get(1.0, tk.END).strip())
    messagebox.showinfo("Information", "Encrypted text copied to clipboard!")

# Function to paste text from clipboard
def paste_from_clipboard():
    entry_decrypt.delete(0, tk.END)
    entry_decrypt.insert(tk.END, root.clipboard_get())

# Function to upload an image
def upload_image():
    global cipher_suite
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", ("*.png", "*.jpg", "*.jpeg", "*.gif"))])
    if file_path:
        fixed_hash = generate_fixed_hash_from_image(file_path)
        key = generate_key_from_hash(fixed_hash)
        cipher_suite = Fernet(key)
        image_path_label.config(text=f"Image uploaded: {file_path}")
        messagebox.showinfo("Information", "Fixed hash and encryption key updated!")

# Create the main window
root = tk.Tk()
root.title("Text Encryption and Decryption")
root.geometry("800x750")

# Field for encrypting text
label_encrypt = tk.Label(root, text="Enter text to encrypt:")
label_encrypt.pack(pady=(20, 5))
entry_encrypt = tk.Entry(root, width=50)
entry_encrypt.pack(pady=5)
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.pack(pady=10)

# Result of encryption
result_encrypt_label = tk.Label(root, text="Encrypted text:")
result_encrypt_label.pack(pady=(20, 5))
result_encrypt = tk.Text(root, height=5, width=50, state=tk.DISABLED)
result_encrypt.pack(pady=5)

# Button to copy encrypted text
copy_button = tk.Button(root, text="Copy Encrypted Text", command=copy_to_clipboard)
copy_button.pack(pady=10)

# Field for decrypting text
label_decrypt = tk.Label(root, text="Enter text to decrypt:")
label_decrypt.pack(pady=(20, 5))
entry_decrypt = tk.Entry(root, width=50)
entry_decrypt.pack(pady=5)
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.pack(pady=10)

# Button to paste text from clipboard
paste_button = tk.Button(root, text="Paste Text from Clipboard", command=paste_from_clipboard)
paste_button.pack(pady=10)

# Result of decryption
result_decrypt_label = tk.Label(root, text="Decrypted text:")
result_decrypt_label.pack(pady=(20, 5))
result_decrypt = tk.Text(root, height=5, width=50, state=tk.DISABLED)
result_decrypt.pack(pady=5)

# Field to upload an image
upload_button = tk.Button(root, text="Upload Image", command=upload_image)
upload_button.pack(pady=10)

# Label to display image upload info
image_path_label = tk.Label(root, text="No image uploaded")
image_path_label.pack(pady=10)

# Start the main loop
root.mainloop()