# Key Library
Here is the list of key libraries related to the PQC utilized in this project:
- **openssl** ([version: 3.3.2](https://github.com/openssl/openssl/releases/tag/openssl-3.3.2))
- **liboqs** ([version: 0.11.0](https://github.com/open-quantum-safe/liboqs/releases/tag/0.11.0))
- **oqs-provider** ([commit hash: 0312c00e33dddf63ce5c0402c162d4ee3169d0b0](https://github.com/open-quantum-safe/oqs-provider/tree/0312c00e33dddf63ce5c0402c162d4ee3169d0b0))
- **qsc-key-encoder** ([commit hash: 1b6289dac9f7caf89d26bad2f1cf3cd628507af2](https://github.com/Quantum-Safe-Collaboration/qsc-key-encoder/tree/1b6289dac9f7caf89d26bad2f1cf3cd628507af2))

# Compile to Linux-x64 (Tested on Ubuntu 22.04)
Let's walk through the process of compiling `lily-pqc` for the `x86-64` architecture. I'll provide a clear step-by-step guide that you can modify to fit your specific requirements.

## Pre-requisite
- Update the all installed packages
```
$ sudo apt update
$ sudo apt upgrade
```

- Install the software tools and libraries that are used to build and compile software:
```
$ sudo apt install build-essential git clang-15 ninja-build curl zip unzip tar pkg-config autoconf autoconf-archive snapd
$ sudo snap install cmake --classic
```

- Clone this project
```
$ git clone --recurse-submodules git@github.com:mraflifirmansyah/lily-pqc.git
```

## Build and Compilation
- Change directory to the cloned repository
```
$ cd lily-pqc
```

- Configure the project
```
$ cmake -DCMAKE_BUILD_TYPE:STRING=Release \
-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
-DCMAKE_C_COMPILER:FILEPATH=/usr/bin/clang-15 \
-DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/clang++-15 \
--no-warn-unused-cli \
-S$(pwd) \
-B$(pwd)/build-x64 \
-GNinja
```

- Build the executable
```
$ cmake --build $(pwd)/build-x64 \
--config Release \
--target lily-pqc
```

- Get the executable from the `build-x64/bin` directory
- Run the executable on a machine that uses `x64` architecture

# Cross-compile to Linux-arm64 (Tested on Ubuntu 22.04)
Cross-compilation is the process of generating executable code for a platform different from the one where the compiler is running. In our case, we aim to cross-compile `lily-pqc` for Raspberry Pi devices, which use the `arm64` architecture.

Let's explore the process of compiling `lily-pqc` specifically for the `arm64/aarch64` architecture. I'll outline a straightforward step-by-step guide that you can customize to suit your specific needs.

## Pre-requisite
- Update the all installed packages
```
$ sudo apt update
$ sudo apt upgrade
```
- Install the software tools and libraries that are used to build and compile software:
```
$ sudo apt install build-essential git clang-15 ninja-build curl zip unzip tar pkg-config autoconf autoconf-archive snapd gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
$ sudo snap install cmake --classic
```

- Clone this project
```
$ git clone --recurse-submodules git@github.com:mraflifirmansyah/lily-pqc.git
```

## Build and Compilation
- Change directory to the cloned repository
```
$ cd lily-pqc
```

- Patch to enable cross-compilation to `arm64` architecture
```
$ git apply cc-arm64-linux.patch
```

- Configure the project
```
$ cmake -DCMAKE_BUILD_TYPE:STRING=Release \
-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
-DCMAKE_C_COMPILER:FILEPATH=/usr/bin/aarch64-linux-gnu-gcc \
-DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/aarch64-linux-gnu-g++ \
--no-warn-unused-cli \
-S$(pwd) \
-B$(pwd)/build-arm64 \
-GNinja
```

- Build the executable
```
$ cmake --build $(pwd)/build-arm64 \
--config Release \
--target lily-pqc
```

- Get the executable from the `build-arm64/bin` directory
- Copy the executable to your RaspberryPi that uses `arm64` architecture and run the executable there

# Notes on cross compilation to Linux-arm

Cross-compilation to the `arm/armhf` target architecture, used by older 32-bit versions of Raspbian OS, is not feasible for `lily-pqc` due to architectural differences. `armhf` is a 32-bit architecture, while `lily-pqc` may rely on 64-bit specific instructions, optimizations, or dependencies that are incompatible with the limitations of 32-bit systems. As a result, attempting to compile for `armhf` could lead to performance issues or outright failures due to these incompatibilities. Therefore, cross-compiling for newer 64-bit architectures like `arm64` is recommended.
