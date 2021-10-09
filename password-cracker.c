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

#define DICTIONARY_FILE "dictionary-preprocessed.txt"
#define DICTIONARY_HASH "dictionary-hash.txt"

#define DICTIONARY_LEN_TOTAL 439812
#define DICTIONARY_PREHASHED 140000

#define INPUT_FILE "hashedPasswords.txt"
#define OUTPUT_FILE "Passwords.txt"
#define SALT "SKKU seclab"
#define ITERATIONS 10000
#define KEY_LEN 16
#define PASSWORD_MAX_LEN 100

struct hm_entry {
    /* Reserve 1 byte for string terminator */
    char key_hex[KEY_LEN * 2 + 1];
    char pass[PASSWORD_MAX_LEN];
};
struct input_entry {
    int id;
    char name[PASSWORD_MAX_LEN];
    char key_hex[KEY_LEN * 2 + 1];
};
struct output_entry {
    int id;
    char name[50];
    char pass[PASSWORD_MAX_LEN];
    bool cracked;
};

bool output_hm_iter(const void *item, void *udata)
{
    const struct output_entry *hm = item;
    printf("id: %d, name: %s, hash: %s, cracked: %s \n", hm->id, hm->name,
           hm->pass, hm->cracked ? "yes" : "no");
    return true;
}

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

uint64_t output_hm_hash(const void *item, uint64_t seed0, uint64_t seed1)
{
    const struct output_entry *hm = item;
    return hashmap_sip(&hm->id, sizeof(int), seed0, seed1);
}

int output_hm_compare(const void *a, const void *b, void *udata)
{
    const struct output_entry *hm_a = a;
    const struct output_entry *hm_b = b;
    return (hm_a->id != hm_b->id);
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
struct hashmap *output_hm;
pthread_mutex_t hm_mutex;

struct thread_args {
    struct hashmap *hm;
    int count;
    char *pass;
    char *key_b64;
    bool calculate_hash;
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

void create_key_hex_from_password(const char *pass, char *key_hex)
{
    uint8_t key[KEY_LEN + 1];
    /* uint8_t key_hex[2 * KEY_LEN + 1]; */

    PBKDF2_HMAC_SHA512(pass, strlen(pass), SALT, strlen(SALT), ITERATIONS,
                       KEY_LEN, key);
    bin_to_hex(key, KEY_LEN, key_hex);
    memcpy(key_hex, key_hex, KEY_LEN * 2);
}

void parse_b64_into_hex(const char *b64, char *hex)
{
    char key_bin[KEY_LEN + 1];

    Base64decode(key_bin, b64);
    bin_to_hex(key_bin, KEY_LEN, hex);
}

void create_entry(char *pass, char *key_b64, bool calculate_hash,
                  struct hm_entry *item)
{
    /* printf("line: %s\n", line); */
    /* struct hm_entry item; // = calloc(sizeof(struct hm_entry), 1); */
    memset(item, 0, sizeof(struct hm_entry));

    /* make sure no stray bytes */

    /* printf("Pass: %s\n", pass); */
    /* printf("Hex: %s\n", key_b64); */
    remove_newline(pass);
    memcpy(item->pass, pass, strlen(pass));
    if (!calculate_hash) {
        remove_newline(key_b64);
        parse_b64_into_hex(key_b64, (char *)item->key_hex);
    } else {
        create_key_hex_from_password(pass, (char *)item->key_hex);
    }
};
int create_entry_and_insert_hm(struct hashmap *hm, char *pass, char *key_b64,
                               bool calculate_hash)
{
    struct hm_entry item;
    create_entry(pass, key_b64, calculate_hash, &item);
    /* Insert item to HM */
    hashmap_set(hm, &item);
    return 1;
};

void *pthread_create_entry_and_insert_hm(void *arguments)
{
    struct thread_args *args = (struct thread_args *)arguments;

    /* printf("line: %s\n", args->line); */
    struct hm_entry item;
    create_entry(args->pass, args->key_b64, args->calculate_hash, &item);
    pthread_mutex_lock(&hm_mutex);
    if (args->count % 100000 == 0)
        printf("Thread %d done\n", args->count);
    /* printf("%s\n", item.pass); */
    /* printf("%s\n", item.key_hex); */
    hashmap_set(hm, &item);
    pthread_mutex_unlock(&hm_mutex);

    /* Free all resources used */

    free(args->pass);
    free(args->key_b64);
    free(args);
    /* pthread_exit(NULL); */
    return NULL;
};

void populate_dictionary_hm(struct hashmap *hm, const char *dictionary_file,
                            const char *dictionary_hash_file, int read_count,
                            bool use_thread, int num_threads)
{
    /* For file and hash */
    FILE *fp = NULL;
    FILE *fp_h = NULL;
    int count = 0;
    int i;
    char *pass = NULL;
    char *key_b64 = NULL;
    size_t len = 0;
    size_t len_2 = 0;
    int read, read_h;
    bool done_read_hash = false;
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

    printf("Loading %d password from file %s and hashes from %s to memory...\n",
           read_count, dictionary_file, dictionary_hash_file);

    clock_gettime(CLOCK_MONOTONIC, &begin);
    fp = fopen(dictionary_file, "r");
    if (fp == NULL) {
        printf("ERROR: cannot open %s\n", dictionary_file);
        exit(-1);
    }

    if (dictionary_hash_file != NULL) {
        fp_h = fopen(dictionary_hash_file, "r");
        if (fp_h == NULL) {
            printf("ERROR: cannot open %s\n", dictionary_file);
            exit(-1);
        }
    } else {
        done_read_hash = true;
    }

    while (1) {
        read = getline(&pass, &len, fp);
        if (read <= -1)
            break;

        if (done_read_hash != true) {
            read = getline(&key_b64, &len_2, fp_h);
            if (read <= -1) {
                /* free(key_b64); */
                printf("Read all of the hashes!, count = %d\n", count);
                done_read_hash = true;
            }
        }
        /* key_b64 = NULL; */

        if (!use_thread) {
            create_entry_and_insert_hm(hm, pass, key_b64, done_read_hash);
            free(pass);
            free(key_b64);
        } else {
            args = malloc(sizeof(struct thread_args));
            args->hm = hm;

            args->pass = pass;
            args->key_b64 = key_b64;
            args->calculate_hash = done_read_hash;
            args->count = count;
            thpool_add_work(pool, pthread_create_entry_and_insert_hm,
                            (void *)args);
        }

        pass = NULL;
        key_b64 = NULL;
        count++;
        if (count == read_count) {
            break;
        }
    }

    if (use_thread) {
        printf("Waiting for threads %d to finish\n", count);
        thpool_wait(pool);
    }
    printf("Finished, populated %d passwords\n", count);

    fclose(fp);
    if (fp_h != NULL)
        fclose(fp_h);
    thpool_destroy(pool);
    clock_gettime(CLOCK_MONOTONIC, &end);
    execution_time = end.tv_sec - begin.tv_sec;
    execution_time += (end.tv_nsec - begin.tv_nsec) / 1000000000.0;

    /* execution_time = (double)() - time) / CLOCKS_PER_SEC; */
    printf("Took %f seconds\n", execution_time);
    /* for (i = 0; i < 1000; i++) */
    /*   printf("%.*s\n", PASSWORD_MAX_LEN, &dictionary[i]); */
}

int parse_line_into_output_entry(char *line, struct output_entry *entry)
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
    memcpy(entry->name, token, strlen(token));

    /* key_hex */
    token = strtok(NULL, delim);
    if (token == NULL)
        return -1;
    memcpy(entry->pass, token, strlen(token));
    entry->cracked = false;
    return 1;
}
void load_output_hm(struct hashmap *output_hm, const char *input_file)
{

    FILE *fp = NULL;
    char *line = NULL;
    int read, len = 0;

    struct timespec begin, end;
    double execution_time;
    struct output_entry entry;

    printf("Reading input file %s ...\n", input_file);
    clock_gettime(CLOCK_MONOTONIC, &begin);
    fp = fopen(input_file, "r");
    while (1) {
        memset(&entry, 0, sizeof(struct output_entry));
        read = getline(&line, &len, fp);
        if (read == -1 || line == NULL)
            break;
        /* printf("Got line: %s\n", line); */
        /* entry = malloc(sizeof(struct input_entry)); */
        parse_line_into_output_entry(line, &entry);
        /* struct hm_entry item; */
        /* create_entry(pass, key_b64, calculate_hash, &item); */
        /* Insert item to HM */
        /* printf("Processing entry %d, name: %s, key_hex: %s\n", entry.id, */
        /*        entry.name, entry.pass); */
        hashmap_set(output_hm, &entry);
        /* if (count % 1000 == 0) */
        /*   printf("Populated %d passwords\n", count); */
    }

    /* printf("Finished, cracked %d passwords\n", cracked); */

    fclose(fp);
    clock_gettime(CLOCK_MONOTONIC, &end);
    execution_time = end.tv_sec - begin.tv_sec;
    execution_time += (end.tv_nsec - begin.tv_nsec) / 1000000000.0;

    /* execution_time = (double)() - time) / CLOCKS_PER_SEC; */
    printf("Took %f seconds\n", execution_time);
    /* for (i = 0; i < 1000; i++) */
    /*   printf("%.*s\n", PASSWORD_MAX_LEN, &dictionary[i]); */
}
void try_crack_id_with_dictionary(struct hashmap *output_hm, int id,
                                  struct hashmap *dictionary)
{
    char *found_password = NULL;
    struct output_entry *entry;

    entry = hashmap_get(output_hm, &(struct output_entry){.id = id});
    if (!entry->cracked) {
        printf("Trying to crack id: %d, name: %s, hash: %s ... \n", entry->id,
               entry->name, entry->pass);

        if (hm_search(dictionary, entry->pass, &found_password) != -1) {
            struct output_entry update;
            memset(&update, 0, sizeof(struct output_entry));
            update.id = id;
            update.cracked = true;
            memcpy(update.pass, found_password, strlen(found_password));
            memcpy(update.name, entry->name, strlen(entry->name));

            printf("Found password in hashmap: %s\n", found_password);
            hashmap_set(output_hm, &update);
        }
    }
}

void output_hashmap_to_file(struct hashmap *output_hm, const char *file_name)
{
    FILE *fp = NULL;
    int i = 0;
    struct output_entry *entry;
    fp = fopen(file_name, "w");
    if (fp == NULL) {
        printf("ERROR: cannot open %s\n", file_name);
        exit(-1);
    }
    for (i = 1; i <= hashmap_count(output_hm); i++) {
        entry = hashmap_get(output_hm, &(struct output_entry){.id = i});
        fprintf(fp, "%d:%s:%s\n", entry->id, entry->name, entry->pass);
    }
}

int main()
{
    int i, count = 0;
    printf("Initializing hashmap with initial capacity: %ld \n",
           sizeof(struct hm_entry) * DICTIONARY_LEN_TOTAL);
    output_hm = hashmap_new(sizeof(struct output_entry),
                            100000 * sizeof(struct output_entry), 0, 0,
                            output_hm_hash, output_hm_compare, NULL);

    hm = hashmap_new(sizeof(struct hm_entry),
                     sizeof(struct hm_entry) * DICTIONARY_LEN_TOTAL, 0, 0,
                     hm_hash, hm_compare, NULL);
    populate_dictionary_hm(hm, DICTIONARY_FILE, DICTIONARY_HASH,
                           DICTIONARY_LEN_TOTAL, true, 128);
    load_output_hm(output_hm, INPUT_FILE);
    printf("Total dictionary entries: %ld\n", hashmap_count(hm));
    printf("Total input entries: %ld\n", hashmap_count(output_hm));
    count = hashmap_count(output_hm);

    for (i = 1; i <= count; i++) {
        try_crack_id_with_dictionary(output_hm, i, hm);
    }
    output_hashmap_to_file(output_hm, OUTPUT_FILE);

    /* Dump content */
    /* hashmap_scan(output_hm, output_hm_iter, NULL); */
    /* hashmap_scan(hm, hm_iter, NULL); */
}
