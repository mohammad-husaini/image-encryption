# Image Encryption and Decryption

This C++ program performs image encryption and decryption using the Rijndael (AES) algorithm and RC4 stream cipher. It utilizes the Crypto++ library for cryptographic operations and the OpenCV library for image processing.

## Features

- Image encryption: Encrypts the selected image using the Rijndael algorithm in CBC mode with a randomly generated key and initialization vector (IV).
- Image decryption: Decrypts the encrypted image using the Rijndael algorithm and the corresponding key and IV.
- Change image directory: Allows the user to change the directory of the selected image.
- Show the image: Displays the selected image using the OpenCV library.

## Dependencies

- Crypto++: A cryptographic library for C++.
- OpenCV: A library for computer vision and image processing.

Make sure to install the required libraries before compiling and running the program.

## Usage

1. Compile the C++ source code along with the Crypto++ and OpenCV libraries.
2. Run the compiled program.
3. Select the desired operation by entering the corresponding number.
4. Follow the on-screen instructions, such as changing the image directory or selecting an image to encrypt or decrypt.
5. The program will encrypt or decrypt the selected image and display the result.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
