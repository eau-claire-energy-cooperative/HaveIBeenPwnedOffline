#!/usr/bin/python3
# -*- coding: utf-8 -*-
from __future__ import division, print_function, unicode_literals
from hashlib import sha1
from os import stat
import argparse
import logging

def binary_search(hex_hash, list_file, file_size):
    def get_full_line(file, pos):
        file.seek(pos)
        while pos > 0 and file.read(1) != "\n":
            pos -= 1
            file.seek(pos)
        return file.readline(), pos

    def search_hash(file, my_hash, start, end):
        if start >= end:
            return 0
        new_pos = start + (end - start) // 2
        candidate_line, pivot = get_full_line(file, new_pos)
        # print("Trying line at pos {:11d}: \"{}\" (pivot position: {})".format(
        #     new_pos, candidate_line.strip(), pivot))
        pwned_hash, count = candidate_line.split(':')
        if pwned_hash == my_hash:
            logger.debug("Password found at byte {:11d}: \"{}\"".format(pivot, candidate_line.strip()))
            return int(count.strip())
        if my_hash > pwned_hash:
            return search_hash(file, my_hash, file.tell(), end)
        else:
            return search_hash(file, my_hash, start, pivot)

    return search_hash(list_file, hex_hash, 0, file_size)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test passwords locally.' +
                                        ' Each password hash in the file will be' +
                                        ' searched for in the list.')
    parser.add_argument('passwords', nargs='+')
    parser.add_argument('--pwned-passwords-ordered-by-hash-filename', required=False,
                        default="pwned-passwords-sha1-ordered-by-hash-v4.txt")
    parser.add_argument('--skip-not-found',action='store_true',required=False,help="skip log messages for passwords that are not found")
    parser.add_argument('--log',type=str,required=False,default="INFO")
    args = parser.parse_args()

    #configure logger
    numeric_level = getattr(logging, args.log.upper())
    logging.basicConfig(level=numeric_level,format='%(message)s')
    logger = logging.getLogger("pwned_offline")

    with open(args.pwned_passwords_ordered_by_hash_filename, 'r') as pwned_passwords_file:
        pwned_passwords_file_size = stat(args.pwned_passwords_ordered_by_hash_filename).st_size
        logger.debug("File size: {} Bytes".format(pwned_passwords_file_size))

        lineNum = 1
        for password in args.passwords:
            hash = password.strip()

            if(hash != ""):
                count = 0
                logger.debug("Searching for hash {} at line {}".format(hash,lineNum))
                count += binary_search(hash, pwned_passwords_file, pwned_passwords_file_size)

                if count > 0:
                    logger.info("Password {} \"{}\" was in {} leaks or hacked databases!".format(lineNum,hash,count) +
                          " Please change it immediately.")
                elif(not args.skip_not_found):
                    logger.info("Password {} \"{}\" is not in the dataset. You may relax.".format(lineNum,hash))
            lineNum += 1
