# Hash Calculator

Hash Calculator es una herramienta de línea de comandos para calcular los tiempos de varios hashes criptográficos de una cadena de entrada. Soporta múltiples algoritmos de hash, incluyendo MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, RIPEMD-160, Whirlpool, BLAKE2 y BLAKE3.

## Características

- Soporte para múltiples algoritmos de hash.
- Medición del tiempo de cálculo para cada hash.
- Fácil de usar desde la línea de comandos.

## Algoritmos soportados

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

## Requisitos

- OpenSSL
- Biblioteca BLAKE2 (https://github.com/BLAKE2/BLAKE2/tree/master)
- Biblioteca BLAKE3-tiny (https://github.com/michaelforney/blake3-tiny/tree/main) 

## Compilación

### En Linux

git clone https://github.com/DavidSotoDalmau/HashTimeChecker.git 
cd HashTimeChecker
make

## Uso

HashTimeChecker "TEXTO_A_HASHEAR"
