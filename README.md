# Find Duplicates and Delete

A program made with GPT to delete duplicate files on current folder recursively.

I changed to C because is faster than other languages.

This program helped me a lot to gain space on my storage server.

## Requirements

```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# Arch
sudo pacman -S openssl
```

## Building

```bash
gcc -o deldup main.c -lcrypto
```

### TO-DO

- Create log of deleted files with path
