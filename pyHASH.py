import hashlib
import os
from colorama import Fore


print( "\n" + Fore.BLUE + "[--help] for the help menu" + "\n" + Fore.BLUE + "[--crack] to start cracking" + "\n")
while True:
    command_hash = input(Fore.GREEN + "[+] Enter a command: ")
    if command_hash == "--crack":
        mode = input(Fore.GREEN + "[+] Enter the mode: ")
        if mode == "md5":
            cracked = 0

            print(
                Fore.GREEN +
                """
    
                 _   _           _      ____                _             
                | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | _____ _ __ 
                | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
                |  _  | (_| \__ \ | | | |___| | | (_| | (__|   <  __/ |   ~>HashCracker<~
                |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~ 
    
    
    
                """
            )

            pass_hash = input(Fore.GREEN + "[+] Enter the md5 hash to crack: ")
            wordlist = input(Fore.GREEN + "[+] Enter the wordlist: ")

            pass_file = open(os.path.join(wordlist), "rb")

            for word in pass_file:
                enc = word
                hash_md5 = hashlib.md5(enc.strip()).hexdigest()


                if pass_hash == hash_md5:
                    print(Fore.BLUE + "[!] Ignore the b'' ")
                    print(Fore.GREEN + "[!!!] Password cracked: " + str(word))
                    cracked = 1

            if cracked == 0:
                print("The password is not in the list")

        elif mode == "sha1":

            print(
                Fore.GREEN +
                """
    
                 _   _           _      ____                _             
                | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | _____ _ __ 
                | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
                |  _  | (_| \__ \ | | | |___| | | (_| | (__|   <  __/ |   ~>HashCracker<~
                |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~ 
    
    
    
                """
            )

            cracked2 = 0

            hash_pass = input(Fore.GREEN + "[+] Enter sha1 hash to crack: ")
            wordlist = input(Fore.GREEN + "[+]Enter the wordlist: ")

            file_pass = open(os.path.join(wordlist), "rb")

            for word2 in file_pass:
                enc_word = word2
                digest = hashlib.sha1(enc_word.strip()).hexdigest()

                if hash_pass == digest:
                    print(Fore.BLUE + "[!] Ignore the b'' ")
                    print(Fore.GREEN + "[!!!] Password cracked: " + str(word2) + "\n")
                    cracked2 = 1
            if cracked2 == 0:
                print(Fore.BLUE + "[!] The password is not in the list")

        elif mode == "sha224":

            print(
                Fore.GREEN +
                """
    
                 _   _           _      ____                _             
                | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | _____ _ __ 
                | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
                |  _  | (_| \__ \ | | | |___| | | (_| | (__|   <  __/ |   ~>HashCracker<~
                |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~ 
    
    
    
                """
            )

            pass_hash = input(Fore.GREEN + "[+] Enter the sha224 to crack: ")
            wordlist = input(Fore.GREEN + "[+] Enter the wordlist: ")


            file_pass = open(os.path.join(wordlist), "rb")



            cracked4 = 0
            for word3 in file_pass:
                enc2 = word3
                sha224 = hashlib.sha224(enc2.strip()).hexdigest()
                if sha224 == pass_hash:
                    print(Fore.BLUE + "[!] Ignore the b'' ")
                    print(Fore.GREEN + "[!!!] Password cracked: " + str(word3) + "\n")
                    cracked4 = 1

            if cracked4 == 0:
                print("The password is not in the list")

        elif mode == "sha256":

            print(
                Fore.GREEN +
                """
    
                 _   _           _      ____                _             
                | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | _____ _ __ 
                | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
                |  _  | (_| \__ \ | | | |___| | | (_| | (__|   <  __/ |   ~>HashCracker<~
                |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~ 
    
    
    
                """
            )

            cracked = 0

            pass_hash = input(Fore.GREEN + "[+] Enter the sha256 hash to crack: ")
            wordlist = input(Fore.GREEN + "[+] Enter the wordlist: ")

            file_pass = open(os.path.join(wordlist), "rb")



            for word in file_pass:
                enc_word = word
                sha256_hash = hashlib.sha256(enc_word.strip()).hexdigest()


                if sha256_hash == pass_hash:
                    print(Fore.BLUE + "[!] Ignore the b'' ")
                    print(Fore.GREEN + "[!!!] Password cracked: " + str(word) + "\n")
                    cracked = 1

            if cracked == 0:
                print("The password is not in the list")

        elif mode == "sha384":

            print(
                Fore.GREEN +
                """
    
                 _   _           _      ____                _             
                | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | _____ _ __ 
                | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
                |  _  | (_| \__ \ | | | |___| | | (_| | (__|   <  __/ |   ~>HashCracker<~
                |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~ 
    
    
    
                """
            )

            cracked = 0

            pass_hash = input(Fore.GREEN + "[+] Enter the sha384 hash you want to crack: ")
            pass_file = input(Fore.GREEN + "[+] Enter the wordlist: ")

            wordlist = open(os.path.join(pass_file), "rb")

            for word in wordlist:

                enc_word = word
                sha384 = hashlib.sha384(enc_word.strip()).hexdigest()

                if sha384 == pass_hash:
                    print(Fore.BLUE + "[!] Ignore the b'' ")
                    print(Fore.GREEN + "[!!!] Password cracked: " + str(word) + "\n")
                    cracked = 1

            if cracked == 0:
                print("The password is not in the list")

        elif mode == "sha512":

            print(
                Fore.GREEN +
                """
    
                 _   _           _      ____                _             
                | | | | __ _ ___| |__  / ___|_ __ __ _  ___| | _____ _ __ 
                | |_| |/ _` / __| '_ \| |   | '__/ _` |/ __| |/ / _ \ '__|
                |  _  | (_| \__ \ | | | |___| | | (_| | (__|   <  __/ |   ~>HashCracker<~
                |_| |_|\__,_|___/_| |_|\____|_|  \__,_|\___|_|\_\___|_|  ~~>Made by tfwcodes(github)<~~ 
    
    
    
                """
            )

            cracked = 0

            pass_hash = input(Fore.GREEN + "[+] Enter the sha512 hash to crack: ")
            pass_file = input(Fore.GREEN + "[+] Enter the wordlist: ")

            wordlist = open(os.path.join(pass_file), "rb")

            for word in wordlist:
                enc_word = word
                sha512 = hashlib.sha512(enc_word.strip()).hexdigest()

                if sha512 == pass_hash:
                    print(Fore.BLUE + "[!] Ignore the b''and the '\r\n' ")
                    print(Fore.GREEN + "[!!!] Password cracked: " + str(word))
                    cracked = 1
            if cracked == 0:
                print("The password in the list")

    elif command_hash == "--help":
        print(Fore.BLUE + "All the mods are: ")
        print(Fore.BLUE + "[md5] to crack md5 hash")
        print(Fore.BLUE + "[sha1] to crack sha1 hash")
        print(Fore.BLUE + "[sha224] to crack sha224 hash")
        print(Fore.BLUE + "[sha256] to crack sha256 hash")
        print(Fore.BLUE + "[sha384] to crack sha384 hash")
        print(Fore.BLUE + "[sha512] to crack sha512 hash" + "\n")
