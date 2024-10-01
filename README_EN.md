# Hash Calculator

Hash Calculator is a command-line tool for calculating the times of various cryptographic hashes for a given input string. It supports multiple hash algorithms, including MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, RIPEMD-160, Whirlpool, BLAKE2, and BLAKE3.

## Features

- Support for multiple hash algorithms.
- Measurement of calculation time for each hash.
- Easy to use from the command line.
- Support for average time in N iterations.

## Supported Algorithms

- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA3-256
- SHA3-512
- RIPEMD-160
- Whirlpool
- BLAKE2b
- BLAKE2bp
- BLAKE3

## Requirements

- OpenSSL
- BLAKE2 Library (https://github.com/BLAKE2/BLAKE2/tree/master)
- BLAKE3-tiny Library (https://github.com/michaelforney/blake3-tiny/tree/main)

## Compilation

### On Linux

- git clone https://github.com/DavidSotoDalmau/HashTimeChecker.git 
- cd HashTimeChecker
- make

## Uso

- HashTimeChecker "TEXT_TO_BE_HASHED" [Iterations]
