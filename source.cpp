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

int encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER* (*cipher)(), unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
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

int decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER* (*cipher)(), unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
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

int main (void)
{
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x0f";
    const EVP_CIPHER* (*cipher)() = EVP_aes_256_ecb;

    unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

    //encrypt_decrypt(plaintext, cipher, key, iv);
    char pad[] = "avadsfadsfasddf";
    int fd = open("plaintext.txt", O_RDONLY);
    char buffer[256];
    int length = read(fd, buffer, sizeof(buffer));
    close(fd);

    return 0;
}
