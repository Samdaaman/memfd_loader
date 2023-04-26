# Memfd Loader
> By using _memfd_create_ to create file pointer to an in-memory file and _execveat_ to execute a file pointer like a regular file, we are able to execute a binary that is entirely stored in memory

Proof of concept reflective (in-memory) loader with encryption. Supports loading a binary securely either via stdio (from a parent process) or a TCP socket. The use case is to allow secure execution of processes directly into memory (ie without creating a file on disk or downloading in cleartext with wget). This could be used as a means for secure delpoyment of a beacon/second-stage in a red-team scenario. The compiled loader is only 25KB in size.


## Technical notes
- Crypto functionality utilised from [TweetNaCl](http://tweetnacl.cr.yp.to/software.html) and it uses [Box](https://nacl.cr.yp.to/box.html) (public/private key encryption mechanism that uses _curve25519_ and _salsa20poly1305_)
- [dietlibc](https://www.fefe.de/dietlibc/) is used to create very small statically linked binaries ~25KB
- Key functions:
    - [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html) - create a file pointer to a fake in-memory file that behaves like a regular `FILE *` (note in this implementation this is implemented with syscalls as dietlibc didn't support it)
    - `execveat(<fp>, "", <argv>, <env>, AT_EMPTY_PATH);` - allows executing a `FILE *` instead of a filepath

## TCP Loader
Sends encrypted binary over TCP, decrypts and executes in memory.
- Compile tcp loader & test binary (see below)
- Start server `python3 server.py`
- Run compiled loader `./main`

## Stdio Loader
Sends encrypted binary to a subprocess, decrypts and executes in memory.
- Compile stdio loader & test binary (see below)
- Start stager `python3 stager.py`



## Compiling
### Setup
```sh
apt install dietlibc-dev
pip3 install pynacl
```

### Commands
 - Run from either `/stdio_loader` or `/tcp_loader` directories
    ```sh
    diet -Os gcc -o main main.c execveat.S tweetnacl.c -Wall -s
    ```
    - `-Os` - optimise diet compiler for size
    - `-s` - strip debug symbols
    - `-Wall` - show all warnings

- Run from `/test` directory
    ```sh
    gcc -o main main.c
    ```
