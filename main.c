#define _XOPEN_SOURCE 500

#include <ftw.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

#define MAX_PATH 4096
#define HASH_STR_LEN (SHA256_DIGEST_LENGTH * 2 + 1)

typedef struct FileNode {
    char hash[HASH_STR_LEN];
    char path[MAX_PATH];
    struct FileNode *next;
} FileNode;

FileNode *head = NULL;

int hash_file(const char *filename, char *output_hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) return -1;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fclose(file);
        return -1;
    }

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return -1;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output_hash + (i * 2), "%02x", hash[i]);
    }
    output_hash[hash_len * 2] = '\0';

    return 0;
}

int is_duplicate(const char *hash, char *original_path) {
    FileNode *current = head;
    while (current) {
        if (strcmp(current->hash, hash) == 0) {
            if (original_path) strncpy(original_path, current->path, MAX_PATH);
            return 1;
        }
        current = current->next;
    }
    return 0;
}

void add_file(const char *hash, const char *path) {
    FileNode *node = malloc(sizeof(FileNode));
    strncpy(node->hash, hash, HASH_STR_LEN);
    strncpy(node->path, path, MAX_PATH);
    node->next = head;
    head = node;
}

int process_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    if (typeflag != FTW_F)
        return 0;

    char hash[HASH_STR_LEN];
    if (hash_file(fpath, hash) != 0) {
        fprintf(stderr, "Failed to hash: %s\n", fpath);
        return 0;
    }

    char original[MAX_PATH];
    if (is_duplicate(hash, original)) {
        printf("Duplicate:\n  %s\n  -> Deleting: %s\n", original, fpath);
        if (remove(fpath) != 0) {
            perror("Error deleting file");
        }
    } else {
        add_file(hash, fpath);
    }

    return 0;
}

void free_list() {
    FileNode *current = head;
    while (current) {
        FileNode *tmp = current;
        current = current->next;
        free(tmp);
    }
}

int main() {
    if (nftw(".", process_file, 20, FTW_PHYS) == -1) {
        perror("nftw");
        return 1;
    }

    free_list();
    return 0;
}

