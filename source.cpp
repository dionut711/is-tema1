#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

const char * ERROR_MESSAGE_CTX = "Creating context failed.";
const char * ERROR_MESSAGE_ENCRYPT_INIT = "EncryptInit failed.";
const char * ERROR_MESSAGE_ENCRYPT_UPDATE = "EncryptUpdate failed.";
const char * ERROR_MESSAGE_ENCRYPT_FINAL = "EncryptFinal failed.";
const char * ERROR_MESSAGE_DECRYPT_INIT = "DecryptInit failed.";
const char * ERROR_MESSAGE_DECRYPT_UPDATE = "DecryptUpdate failed.";
const char * ERROR_MESSAGE_DECRYPT_FINAL = "DecryptFinal failed.";

const int TEXT_SIZE = 256;
const int DICTIONARY_SIZE = 1024 * 1024;
const char * CIPHERTEXT_PATH = "ciphertext.txt";

void printError(const char * message, bool exit = true)
{
    printf("ERROR: %s\n", message);
    if(exit) abort();
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

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + output_length, &output_length));
        //printError(ERROR_MESSAGE_DECRYPT_FINAL, false);
    plaintext_length += output_length;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_length;
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

unsigned char* findKey(unsigned char* plaintext, unsigned char* ciphertext, const EVP_CIPHER* (*cipher)(), unsigned char* iv, unsigned char** words, int words_count) {

    unsigned char* deciphertext = (unsigned char*)malloc(sizeof(unsigned char) * TEXT_SIZE);

    for (int i = 0; i < words_count; i++) {
        unsigned char* current_key = padKey(words[i], '\x20', 17);
        int dechipertext_length = decrypt(ciphertext, strlen((char*)ciphertext), cipher, current_key, iv, deciphertext);
        deciphertext[dechipertext_length] = 0;

        int same = !strcmp((char*)plaintext, (char*)deciphertext);

        if (same) {
            printf("key found:\n%s\n\n", current_key);
            printf("attempts:\n%d\n\n", i);
            printf("plaintext:\n%s\n\n", plaintext);
            return current_key;
        }
        free (current_key);
    }

    return nullptr;
}

int main (int argc, char* argv[])
{
    // Read dictionary from file
    char dictionary[DICTIONARY_SIZE];
    int fd_dict = open("word_dict.txt", O_RDONLY);
    int dictionary_length = read(fd_dict, dictionary, sizeof(dictionary));
    dictionary[dictionary_length] = 0;
    close(fd_dict);

    // Create words array from dictionary
    int words_count;
    unsigned char** words  = splitLines((unsigned char*)dictionary, &words_count);



    unsigned char *iv = (unsigned char *)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    unsigned char* key;
    const EVP_CIPHER* (*cipher)();
    char* textpath;


    // Argument parsing
    if(argc > 1) {
        if (!strcmp(argv[1], "ecb"))
            cipher = EVP_aes_128_ecb;
        else if (!strcmp(argv[1], "obf"))
            cipher = EVP_aes_128_ofb;
        else {
            printf("Invalid mode, please choose 'ecb' or 'obf'.\n");
            return 0;
        }

        printf("mode: %s\n", argv[1]);

        if(argc > 2) {
            textpath = argv[2];

            if (argc > 3) {
                key = padKey((unsigned char*)argv[3], '\x20', 17);
            } else {
                srand(time(NULL));
                key = padKey((unsigned char*)words[rand() % words_count], '\x20', 17);

            }
            printf("key: %s\n\n", key);
        } else {
            printf("Please specifiy a path to the plaintext file.\n");
            return 0;
        }
    }
    else {
        printf("No parameters were given.\n");
        return 0;
    }

    // Read plaintext from file
    unsigned char plaintext[TEXT_SIZE];
    int fd_plain = open(textpath, O_RDONLY);
    int length = read(fd_plain, plaintext, sizeof(plaintext));
    plaintext[length] = 0;
    close(fd_plain);

    // Encyrpt plaintext
    unsigned char ciphertext[TEXT_SIZE];
    int ciphertext_length = encrypt(plaintext, strlen((char*)plaintext), cipher, key, iv, ciphertext);
    printf("ciphertext:\n%s\n\n", ciphertext);

    // Write encrypted text to file
    int fd_cipher = open(CIPHERTEXT_PATH, O_WRONLY | O_CREAT);
    write(fd_cipher, ciphertext, ciphertext_length);
    close(fd_cipher);


    unsigned char* key_found = findKey(plaintext, ciphertext, cipher, iv, words, words_count);
    if(!key_found) {
        printf("No key found.\n");
    }

    return 0;
}
