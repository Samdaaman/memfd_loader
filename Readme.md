# Setup
```sh
apt install dietlibc-dev
pip3 install pynacl
```

# Compiling
```sh
diet -Os gcc -o main main.c execveat.S tweetnacl.c -Wall -s
```
- `-Os` - optimise diet compiler for size
- `-s` - strip debug symbols
- `-Wall` - show all warnings


# Running
```sh
cd server
python3 server.py
```

```sh
cd src
# compile
./main
```
