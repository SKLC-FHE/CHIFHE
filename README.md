Implementation of Fast Blind Rotation for Bootstrapping FHEs
=====================================

## Fast Blind Rotation for Bootstrapping FHEs
The CHIFHE library contains the implementation of the fully homorphic encryption schemes presented in the paper [Fast Blind Rotation for Bootstrapping FHEs](https://eprint.iacr.org/2023/1564) by using [OpenFHE_v1.1.1](https://github.com/openfheorg/openfhe-development/releases/tag/v1.1.1).

### Requirements
A C++ compiler, the NTL libraries.

## Run the code
1. Configure, build and compile the project.
```
mkdir build
cd build
cmake -DWITH_NTL=ON ..
make 
```



