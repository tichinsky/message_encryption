# Text Encryption and Decryption with Image-Based Key

## Overview

This Python application provides functionalities for encrypting and decrypting text using a symmetric encryption scheme. The key for the encryption is derived from an image file chosen by the user. The application uses the `cryptography` library for encryption and decryption, and the `Pillow` library for image processing.

## Features

- **Encrypt Text**: Enter text and encrypt it using a key derived from an image.
- **Decrypt Text**: Enter encrypted text and decrypt it using the same image-derived key.
- **Copy to Clipboard**: Copy the encrypted text to the clipboard for easy sharing.
- **Paste from Clipboard**: Paste text from the clipboard to decrypt.
- **Upload Image**: Upload an image file to generate a fixed hash and encryption key from it.

## Requirements

- Python 3.x
- `cryptography` library
- `Pillow` library
- `numpy` library

You can install the required libraries using pip:

```sh
pip install cryptography Pillow numpy