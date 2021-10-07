/* #include "password-cracker.h" */
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "hashmap.h"
#include "thpool.h"

#define DICTIONARY_FILE "dictionary-preprocessed-with-hash.txt"
#define DICTIONARY_FILE_NO_HASH "dictionary-preprocessed-no-hash.txt"

#define DICTIONARY_LEN_TOTAL 295559
#define DICTIONARY_LEN 200000
#define DICTIONARY_LEN_UNHASHED 95559

#define INPUT_FILE "hashedPasswords.txt"
#define OUTPUT_FILE "Passwords.txt"
#define SALT "SKKU seclab"
#define ITERATIONS 10000
#define KEY_LEN 16
#define PASSWORD_MAX_LEN 7

struct hm_entry {
    /* Reserve 1 byte for string terminator */
    char key_hex[KEY_LEN * 2 + 1];
    char pass[PASSWORD_MAX_LEN + 1];
};
struct input_entry {
    int id;
    char name[64];
    char key_hex[KEY_LEN * 2 + 1];
};
struct output_entry {
    int id;
    char name[64];
    char pass[PASSWORD_MAX_LEN + 1];
};

int hm_compare(const void *a, const void *b, void *udata)
{
    const struct hm_entry *hm_a = a;
    const struct hm_entry *hm_b = b;
    return strcmp(hm_a->key_hex, hm_b->key_hex);
}
uint64_t hm_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const struct hm_entry *hm = item;
    return hashmap_sip(hm->key_hex, strlen(hm->key_hex), seed0, seed1);
}

int hm_search(struct hashmap *hm, const char *key_hex, char **password)
{

    struct hm_entry *entry;
    struct hm_entry query;
    *password = NULL;

    memcpy(query.key_hex, key_hex, strlen(key_hex) + 1);
    entry = hashmap_get(hm, &query);
    if (entry != NULL) {
        printf("The key of hash %s is %s\n", entry->pass, entry->key_hex);
        *password = entry->pass;
        return 1;
    } else {
        return -1;
    }
}

/* Iterate over hashmap and apply the function */
bool hm_iter(const void *item, void *udata)
{
    const struct hm_entry *hm = item;
    printf("key_hex: %s \n", hm->key_hex);
    printf("pass: %s \n", hm->pass);
    return true;
}

void PBKDF2_HMAC_SHA512(const char *pass, int pass_len, const uint8_t *salt,
                        int salt_len, uint32_t iterations, size_t key_len,
                        uint8_t *key)
{
    PKCS5_PBKDF2_HMAC(pass, pass_len, salt, salt_len, iterations, EVP_sha512(),
                      key_len, key);
}

struct hashmap *hm;
pthread_mutex_t hm_mutex;

struct thread_args {
    struct hashmap *hm;
    char *line;
    bool have_hash;
};

void remove_newline(char *str)
{
    char *ptr = str;
    if ((ptr = strchr(str, '\n')) != NULL)
        *ptr = '\0';
}

void bin_to_hex(const char *input, size_t input_len, char *output)
{
    int i;
    for (i = 0; i < input_len; i++) {
        sprintf(output + (i * 2), "%02x", 255 & input[i]);
    }
}

/* void add_hm_entry(struct hashmap *) */

void create_hm_entry_from_password(const char *pass, struct hm_entry *item)
{
    uint8_t key[KEY_LEN + 1];
    uint8_t key_hex[2 * KEY_LEN + 1];

    PBKDF2_HMAC_SHA512(pass, strlen(pass), SALT, strlen(SALT), ITERATIONS,
                       KEY_LEN, key);
    bin_to_hex(key, KEY_LEN, key_hex);

    memcpy(item->pass, pass, strlen(pass));
    memcpy(item->key_hex, key_hex, KEY_LEN * 2);
}

int parse_line_into_hm_entry(char *line, struct hm_entry *item)
{
    const char delim[2] = ":";
    char key[KEY_LEN + 1];
    char key_hex[2 * KEY_LEN + 1];
    char *token;
    remove_newline(line);

    /* Read password */

    token = strtok(line, delim);
    if (token == NULL)
        return -1;
    memcpy(item->pass, token, strlen(token));
    token = strtok(NULL, delim);
    if (token == NULL)
        return -1;

    Base64decode(key, token);
    bin_to_hex(key, KEY_LEN, key_hex);
    memcpy(item->key_hex, key_hex, KEY_LEN * 2);
    return 1;
}
int process_line_and_insert_hm(struct hashmap *hm, char *line, bool have_hash)
{
    /* printf("line: %s\n", line); */
    struct hm_entry item;
    int ret = 1;
    /* Make sure no stray bytes */
    memset(&item, 0, sizeof(struct hm_entry));

    /* Insert item to HM */
    if (have_hash) {
        ret = parse_line_into_hm_entry(line, &item);
        if (ret < 0) {
            return -1;
        }

    } else {
        remove_newline(line);
        create_hm_entry_from_password(line, &item);
    }
    hashmap_set(hm, &item);
    return 1;
    /* printf("%s\n", item.pass); */
    /* printf("%s\n", item.key_hex); */
};
void *pthread_process_line_and_insert_hm(void *arguments)
{
    struct thread_args *args = arguments;

    /* printf("line: %s\n", args->line); */
    struct hm_entry item;
    int ret = 1;
    /* Make sure no stray bytes */
    memset(&item, 0, sizeof(struct hm_entry));

    /* Insert item to HM */
    if (args->have_hash) {
        ret = parse_line_into_hm_entry(args->line, &item);
        if (ret < 0)
            goto exit;
    } else {
        remove_newline(args->line); /*  */
        create_hm_entry_from_password(args->line, &item);
    }
    pthread_mutex_lock(&hm_mutex);
    /* printf("%s\n", item.pass); */
    /* printf("%s\n", item.key_hex); */
    hashmap_set(hm, &item);
    pthread_mutex_unlock(&hm_mutex);

exit:
    free(args->line);
    free(args);
    /* pthread_exit(NULL); */
    return NULL;
};

int populate_dictionary_hm(struct hashmap *hm, const char *dictionary_file,
                           int read_count, bool have_hash, bool use_thread,
                           int num_threads)
{
    FILE *fp = NULL;
    int count = 0;
    int i;
    char *line = NULL;
    size_t len = 0;
    int read;
    /* clock_t time; */
    /* Works better with threads */
    struct timespec begin, end;
    double execution_time;
    threadpool pool;
    struct thread_args *args;

    if (use_thread) {
        printf("Initializing thread pool with %d threads\n", num_threads);
        pool = thpool_init(num_threads);
    }

    printf("Loading %d %s from file %s to memory...\n", read_count,
           have_hash ? "pre-hashed password" : "raw passwords",
           dictionary_file);
    clock_gettime(CLOCK_MONOTONIC, &begin);
    fp = fopen(dictionary_file, "r");
    if (fp == NULL)
        return -1;
    while (1) {
        line = malloc(100);
        read = getline(&line, &len, fp);
        if (read == -1)
            break;
        if (!use_thread) {
            process_line_and_insert_hm(hm, line, have_hash);
            free(line);
        } else {
            args = malloc(sizeof(struct thread_args));
            args->hm = hm;
            args->line = line;
            args->have_hash = have_hash;
            thpool_add_work(
                pool, (void (*)(void *))pthread_process_line_and_insert_hm,
                (void *)args);
        }
        count++;
        if (count == read_count) {
            break;
        }
        /* if (count % 1000 == 0) */
        /*   printf("Populated %d passwords\n", count); */
    }

    if (use_thread) {
        printf("Waiting for threads to finish\n", count);
        thpool_wait(pool);
        thpool_destroy(pool);
    }
    printf("Finished, populated %d passwords\n", count);

    fclose(fp);

    clock_gettime(CLOCK_MONOTONIC, &end);
    execution_time = end.tv_sec - begin.tv_sec;
    execution_time += (end.tv_nsec - begin.tv_nsec) / 1000000000.0;

    /* execution_time = (double)() - time) / CLOCKS_PER_SEC; */
    printf("Took %f seconds\n", execution_time);
    /* for (i = 0; i < 1000; i++) */
    /*   printf("%.*s\n", PASSWORD_MAX_LEN, &dictionary[i]); */
    return 1;
}

int parse_line_into_input_entry(char *line, struct input_entry *entry)
{
    const char delim[2] = ":";
    char *token;
    remove_newline(line);

    /* Format: "id:name:hex_key" */
    /* ID */
    token = strtok(line, delim);
    if (token == NULL)
        return -1;
    entry->id = atoi(token);

    /* name */
    token = strtok(NULL, delim);
    if (token == NULL)
        return -1;
    memset(entry->name, 0, sizeof(entry->name));
    memcpy(entry->name, token, strlen(token));

    /* key_hex */
    token = strtok(NULL, delim);
    if (token == NULL)
        return -1;
    memset(entry->key_hex, 0, sizeof(entry->key_hex));
    memcpy(entry->key_hex, token, KEY_LEN * 2);
    return 1;
}

int read_file_and_try_dictionary(struct hashmap *hm, const char *input_file)
{
    FILE *fp = NULL;
    int cracked = 0;
    int i;
    char *line = NULL;
    char *password = NULL;
    size_t len = 0;
    int read;
    /* clock_t time; */
    /* Works better with threads */
    struct timespec begin, end;
    double execution_time;
    struct input_entry entry;

    printf("Reading input file %s ...\n", input_file);
    fp = fopen(input_file, "r");
    while (1) {
        line = malloc(1000);
        read = getline(&line, &len, fp);
        if (read == -1 || line == NULL)
            break;
        printf("Got line: %s\n", line);
        /* entry = malloc(sizeof(struct input_entry)); */
        parse_line_into_input_entry(line, &entry);
        printf("Processing entry %d, name: %s, key_hex: %s\n", entry.id,
               entry.name, entry.key_hex);
        if (hm_search(hm, entry.key_hex, &password) != -1) {
            printf("Got password: %s\n", password);
            cracked++;
        }
        /* if (count % 1000 == 0) */
        /*   printf("Populated %d passwords\n", count); */
    }

    printf("Finished, cracked %d passwords\n", cracked);

    fclose(fp);

    clock_gettime(CLOCK_MONOTONIC, &end);
    execution_time = end.tv_sec - begin.tv_sec;
    execution_time += (end.tv_nsec - begin.tv_nsec) / 1000000000.0;

    /* execution_time = (double)() - time) / CLOCKS_PER_SEC; */
    printf("Took %f seconds\n", execution_time);
    /* for (i = 0; i < 1000; i++) */
    /*   printf("%.*s\n", PASSWORD_MAX_LEN, &dictionary[i]); */
    return 1;
}

void hash_benchmark()
{
    int ret = 0;
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH, 1000, false, true,
                                 1);
    hashmap_clear(hm, false);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH, 1000, false, true,
                                 8);
    hashmap_clear(hm, false);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH, 1000, false, true,
                                 16);
    hashmap_clear(hm, false);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH, 1000, false, true,
                                 64);
    hashmap_clear(hm, false);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH, 1000, false, true,
                                 128);
    hashmap_clear(hm, false);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH, 1000, false, true,
                                 256);
    hashmap_clear(hm, false);
}

int main()
{
    int ret = 1;
    printf("Initializing hashmap with initial capacity: %ld \n",
           sizeof(struct hm_entry) * DICTIONARY_LEN_TOTAL);
    hm = hashmap_new(sizeof(struct hm_entry),
                     sizeof(struct hm_entry) * DICTIONARY_LEN_TOTAL, 0, 0,
                     hm_hash, hm_compare, NULL);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE, DICTIONARY_LEN, true,
                                 false, 0);
    ret = populate_dictionary_hm(hm, DICTIONARY_FILE_NO_HASH,
                                 DICTIONARY_LEN_UNHASHED, false, true, 128);

    printf("Total dictionary entries: %ld\n", hashmap_count(hm));

    read_file_and_try_dictionary(hm, INPUT_FILE);
    /* hashmap_scan(hm, hm_iter, NULL); */
    /* char *password; */
    /* ret = hm_search("341c7f2a7ee805522a45ab3719333a73", &password); */
    /* printf("Found: %s\n", password); */
}
