#!/usr/bin/env python3

# import requests
import io
import hashlib
from tqdm import tqdm
# import threading
import multiprocessing as mp
import time
import os
from base64 import b64encode, b64decode

dictionary_lines = []
# SIZE_LIMIT = 4000000

# request.get('raw.githubusercontent.com/danielmiessler/SecList/master/Passwords/Common-credentials/10-mil')

for filename in os.scandir("password_lists"):
    print(f"Opening {filename.path}")
    encoding = "utf-8"

    with  io.open(filename, 'r', encoding=encoding, errors="ignore") as f:
        while True:
            line = f.readline()
            if len(line.strip()) >= 7 and any(char.isdigit() for char in line.strip()) :
                dictionary_lines.append(line.strip())
            if not line:
                break


unique_lines = list(set(dictionary_lines))


print("Total number of lines: ", len(unique_lines))
file_name = 'dictionary-preprocessed.txt'
file_name2 = 'dictionary-hash.txt'

# ratio =
# HASH_UNTIL = 140000
HASH_UNTIL = 120000
# TOTAL = 2000
# PASSWORD_UNTIL = 20000

open(file_name, 'w').close()
open(file_name2, 'w').close()

def worker(line, q):
    line_encoded = line.encode('utf-8')
    key = hashlib.pbkdf2_hmac("sha512" ,line_encoded, b"SKKU seclab", 10000, 16)
    # encoded = key.hex().strip()
    encoded = b64encode(key).decode('utf-8').strip()
    message = f'{line}:{encoded}'

    q.put(message)

def listener(q):
    count = 0
    dict_file = file_name
    hash_file = file_name2
    while 1:
        m = q.get()
        if m == 'kill':
            break
        splitted = m.split(":")
        password = splitted[0]
        hashed = splitted[1]
        with open(dict_file, 'a') as f:
            f.write(f'{password}\n')
            f.flush()

        with open(hash_file, 'a') as f:
            f.write(f'{hashed}\n')
            f.flush()




manager = mp.Manager()
q = manager.Queue()
pool = mp.Pool(128)
watcher = pool.apply_async(listener, (q,))

jobs = []
for line in unique_lines[:HASH_UNTIL]:
    job = pool.apply_async(worker, (line,q))
    jobs.append(job)

print("Preparing prehashed dictionary")
for job in tqdm(jobs):
    job.get()

q.put('kill')

pool.close()
pool.join()


print("Writing dictionary to file" , file_name)

for line in tqdm(unique_lines[HASH_UNTIL:]):
    with open(file_name, 'a') as f:
        f.write(f'{line}\n')

print(file_name, os.path.getsize(file_name))
print(file_name2, os.path.getsize(file_name2))
exit()

# print(len(jobs))
