#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

const char * ERROR_MESSAGE_CTX = "Creating context failed.";
const char * ERROR_MESSAGE_ENCRYPT_INIT = "EncryptInit failed.";
const char * ERROR_MESSAGE_ENCRYPT_UPDATE = "EncryptUpdate failed.";
const char * ERROR_MESSAGE_ENCRYPT_FINAL = "EncryptFinal failed.";
const char * ERROR_MESSAGE_DECRYPT_INIT = "DecryptInit failed.";
const char * ERROR_MESSAGE_DECRYPT_UPDATE = "DecryptUpdate failed.";
const char * ERROR_MESSAGE_DECRYPT_FINAL = "DecryptFinal failed.";

void printError(const char * message)
{
    printf("ERROR: %s\n", message);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER* (*cipher)(), unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int output_length;
    int ciphertext_length;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        printError(ERROR_MESSAGE_CTX);

    if(1 != EVP_EncryptInit_ex(ctx, cipher(), NULL, key, iv))
        printError(ERROR_MESSAGE_ENCRYPT_INIT);

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &output_length, plaintext, plaintext_len))
        printError(ERROR_MESSAGE_ENCRYPT_UPDATE);
    ciphertext_length = output_length;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + output_length, &output_length))
        printError(ERROR_MESSAGE_ENCRYPT_FINAL);
    ciphertext_length += output_length;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_length;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER* (*cipher)(), unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int output_length;
    int plaintext_length;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        printError(ERROR_MESSAGE_CTX);

    if(1 != EVP_DecryptInit_ex(ctx, cipher(), NULL, key, iv))
        printError(ERROR_MESSAGE_DECRYPT_INIT);

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &output_length, ciphertext, ciphertext_len))
        printError(ERROR_MESSAGE_DECRYPT_UPDATE);
    plaintext_length = output_length;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + output_length, &output_length))
        printError(ERROR_MESSAGE_DECRYPT_FINAL);
    plaintext_length += output_length;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_length;
}

void encrypt_decrypt(unsigned char* plaintext, const EVP_CIPHER * (*cipher)(), unsigned char* key, unsigned char* iv)
{
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), cipher, key, iv, ciphertext);


    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);


    decryptedtext_len = decrypt(ciphertext, ciphertext_len, cipher, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';


    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);
}

unsigned char* padKey(unsigned char* key, unsigned char character, int length)
{
    unsigned char* new_key = (unsigned char*)malloc(sizeof(unsigned char) * length);

    int min_length = (strlen((char *)key) < length) ? strlen((char *)key) : length;
    for (int i = 0; i < min_length; i++)
        new_key[i] = key[i];
    for (int i = min_length; i < length; i++)
        new_key[i] = character;
    new_key[length] = 0;

    return new_key;
}

unsigned char** splitLines(unsigned char* text, int* lines_count)
{
    int text_length = strlen((char*)text);

    *lines_count = 0;
    for (int i = 0; i < text_length; i++)
        if (text[i] == '\n')
            *lines_count += 1;

    unsigned char** lines = (unsigned char**)malloc(sizeof(unsigned char*) * *lines_count);

    unsigned char* line = text;
    int current_line_index = 0;

    for (int i = 0; i < text_length; i++) {
        if (text[i] == '\n') {
            text[i] = 0;
            lines[current_line_index] = line;
            current_line_index += 1;
            line = text + i + 1;
        }
    }

    return lines;
}

int main (void)
{
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x0f";
    const EVP_CIPHER* (*cipher)() = EVP_aes_128_ecb;

    unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

    //encrypt_decrypt(plaintext, cipher, key, iv);
//    char pad[] = "avadsfadsfasddf";
//    int fd = open("plaintext.txt", O_RDONLY);
//    char buffer[256];
//    int length = read(fd, buffer, sizeof(buffer));
//    close(fd);

    char dictionary[1024 * 1024];
    int fd = open("word_dict.txt", O_RDONLY);
    int dictionary_length = read(fd, dictionary, sizeof(dictionary));
    dictionary[dictionary_length] = 0;

    int lines_count;
    unsigned char** lines  = splitLines((unsigned char*)dictionary, &lines_count);

    //encrypt_decrypt(plaintext, cipher, padKey(lines[0], '\x20', 17), iv);

    unsigned char ciphertext[256];
    unsigned char deciphertext[256];
    key = padKey(lines[1], '\x20', 17);

    encrypt(plaintext, strlen((char*)plaintext), cipher, key, iv, ciphertext);
    //int dechipertext_length = decrypt(ciphertext, strlen((char*)ciphertext), cipher, key, iv, deciphertext);
    //deciphertext[dechipertext_length] = 0;

    for (int i = 0; i < lines_count; i++) {
        unsigned char* current_key = padKey(lines[i], '\x20', 17);
        int dechipertext_length = decrypt(ciphertext, strlen((char*)ciphertext), cipher, current_key, iv, deciphertext);
        deciphertext[dechipertext_length] = 0;

        int same = !strcmp((char*)plaintext, (char*)deciphertext);
        printf("key[%s]: %d\n", current_key, same);
        if (same) break;
    }
    //printf("cmp:%d\n", strcmp((char*)plaintext, (char*)deciphertext));

    return 0;
}
