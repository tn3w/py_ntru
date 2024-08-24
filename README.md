# py_ntru

Welcome to the `py_ntru` documentation! This library provides a Python wrapper around the Rust NTRU library, enabling the use of post-quantum cryptographic algorithms with enhanced performance and availability. The following comprehensive guide will walk you through the installation, building, and usage processes.

## 🚀 Installation

### Prerequisites

Before you begin, ensure you have the following installed on your system:
- **Python 3.7+**: The latest version of Python 3 is recommended. You can download it from the [official Python website](https://www.python.org/downloads/).
- **Rust**: Required for compiling the Rust code. You can install it via [rustup](https://rustup.rs/).

### Virtualenv Setup

Using a virtual environment helps manage dependencies and avoid conflicts. Follow these steps to set it up:

1. **Create a Virtual Environment**

   Run the following command to create a virtual environment in the current directory:

   ```bash
   python -m venv .venv
   ```

2. **Activate the Virtual Environment**

   - On **Linux/macOS**, activate the virtual environment with:

     ```bash
     source .venv/bin/activate
     ```

   - On **Windows**, use:

     ```bash
     .venv\Scripts\activate
     ```

### Installing Dependencies

1. **Install Maturin**

   Maturin is a tool for building and publishing Rust-based Python packages. Install it using pip:

   ```bash
   pip install maturin
   ```

2. **Clone the Repository**

   Clone the `py_ntru` repository from GitHub to your local machine:

   ```bash
   git clone https://github.com/tn3w/py_ntru.git
   ```

3. **Navigate to the Repository Directory**

   Change your working directory to the `py_ntru` directory:

   ```bash
   cd py_ntru
   ```

4. **Build the Python Package**

   Use Maturin to compile the Rust code and create a Python extension wheel. The `--release` flag ensures that the code is optimized for performance:

   ```bash
   maturin build --release
   ```

5. **Locate the Wheel File**

   After building, navigate to the directory where the wheel file is located:

   ```bash
   cd target/wheels
   ```

6. **Install the Wheel File**

   Install the wheel file using pip. Replace `<version>` and `<build>` with the actual version and build number from the wheel file:

   ```bash
   pip install py_ntru-<version>-<build>.whl
   ```

## 🛞 Building Wheels Using Docker

If you prefer to build the package in a Docker container, follow these steps:

1. **Build the Docker Image**

   Use the provided Dockerfile to build the Docker image. This image contains all the necessary dependencies for building `py_ntru`:

   ```bash
   sudo docker build -t py_ntru_builder .
   ```

2. **Run the Docker Container**

   Start a container from the image and mount your local repository directory:

   ```bash
   sudo docker run --rm -it -v $(pwd):/workspace py_ntru_builder
   ```

   Inside the Docker container, navigate to the `/workspace` directory and build the package as described in the [Building the Python Package](#build-the-python-package) section.

## 📝 Usage

Once `py_ntru` is installed, you can use it in your Python scripts. Here is a basic example of how to use the library:

```python
import py_ntru

# Generate a private key
private_key = py_ntru.generate_private_key()
print(f"Private Key: {private_key}")

# Generate a public key based on the private key
public_key = py_ntru.generate_public_key_based_on_private_key(private_key)
print(f"Public Key: {public_key}")

# Message to encrypt
message = b"Hello!"
print(f"Original Message: {message}")

# Encrypt the message using the public key
ciphertext = py_ntru.encrypt(public_key, message)
print(f"Ciphertext: {ciphertext}")

# Decrypt the ciphertext using the private key
decrypted_message = py_ntru.decrypt(private_key, ciphertext)
print(f"Decrypted Message: {decrypted_message}")

```

## 🛠 Troubleshooting

If you encounter any issues during installation or usage, consider the following:

- **Ensure Compatibility**: Check that your versions of Python, Rust, and Maturin are compatible with `py_ntru`.
- **Check Dependencies**: Verify that all necessary dependencies are installed and up-to-date.
- **Consult Logs**: Review error messages and logs for clues on what might be going wrong.

For additional support, you can open an issue on the [GitHub repository](https://github.com/tn3w/py_ntru/issues) or consult the community forums.

## 📚 Contributing

Contributions to `py_ntru` are welcome! If you'd like to contribute, please follow these guidelines:

1. **Fork the Repository**: Create a personal fork of the `py_ntru` repository.
2. **Create a Branch**: Make a new branch for your changes.
3. **Make Changes**: Implement your changes and ensure they adhere to the project's coding standards.
4. **Submit a Pull Request**: Push your branch to your fork and submit a pull request to the main repository.

Thank you for using `py_ntru` and contributing to the advancement of post-quantum cryptography!
