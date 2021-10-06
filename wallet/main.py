from flask import config
from flask.globals import request
import requests
from os import remove, truncate, stat, system
from json import load, dumps, dump
from sys import platform
from pyAesCrypt import encryptFile, decryptFile
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from hashlib import sha512
from base64 import b64decode, b64encode
from colorama import Fore, init
init(autoreset=True)
from time import sleep
class main():
    def __init__(self):
        self.req = requests.Session(),
        self.config = load(open("config.json", "r"))

    def dump_config(self):
        dump(self.config, open("config.json", "w"))

    def create_wallet(self, passphrase):
        wallet = RSA.generate(2048)
        open("private_key.pem", "w").write(str(wallet.export_key("PEM")))
        encryptFile("private_key.pem", "private_key.crazecoin", str(passphrase))
        remove("private_key.pem")
        ip = input("IP to connect : ")
        self.config["IP"] = str(ip)
        self.config["wallet"] = str(wallet.public_key().export_key("PEM"))
        self.config["balance"] = 0
        self.config["setup"] = True
        self.dump_config()
        return True

    def get_back_to_menu(self):
        input("Press any key to get back to menu...")
        self.main_menu()
        # Might get a syntax error with self.main_menu call

    def main_menu(self):
        if(platform == "linux"):system("clear")
        elif(platform == "win32"):system("cls")
        passphrase = input("Passphrase : ")
        try:
            decryptFile("private_key.crazecoin", "private_key.pem", passphrase)
        except:
            self.main_menu()
        choice = input(f"Welcome to the CrazeCoin client wallet! You currently have {Fore.GREEN + requests.post('http://' + self.config['IP'] + '/wallet').json()['value']} CrazeCoins. Made by ScriptedDeveloper on GitHub.\n1 - Send\n2 - Recieve")
        if(choice == "1"):
            addr = input("Address : ")
            value = "Value : "
            confirmation = "Are you sure ? Y/N : "
            data = sha512("wallet")
            data.update(b64encode(data))
            sign = PKCS1_v1_5.new(RSA.import_key(open("private_key.pem", "r").read()))
            sig = sign.sign(data)
            if(confirmation == 'Y'):
                transaction = requests.post(self.config["IP"] + "/send", data={"reciever" : addr, "sender" : self.config["public_key", "amount" : value, "content" : data]})
                if(transaction.status_code == 200):
                    print(f"Successfully sent {Fore.GREEN +  value} CrazeCoins to wallet {Fore.GREEN + addr}!")
                    self.get_back_to_menu()

        elif(choice == "2"):
            if(platform == "linux"):system("clear")
            elif(platform == "win32"):system("cls")
            print(f"Your permanent wallet address is {Fore.GREEN + self.config['public_key']}!")
            self.get_back_to_menu()

    def setup(self):
        if(self.config["setup"] != True):
            if(platform == "linux"):system("clear")
            elif(platform == "win32"):system("cls")
            else:
                print("Sorry. You run either MacOS or an unknown operating system which is not supported. Please use either Linux or Windows.")
                sleep(4)
                exit(0)
            if(self.config["setup"] == False or not self.config["setup"]):
                import_new = input("Welcome to CrazeCoin wallet! For import press **i** and for new **n** : ")
                if(import_new == "n"):
                    passhrase = input("Passphrase : ")
                    self.create_wallet(passhrase)
                    print("Success!")
                    sleep(3)
                    self.main_menu()
                elif(import_new == "i"):
                    if(stat("recovery.json") != 0 and stat("private_key.crazecoin") != 0):
                        recovery = load(open("recovery.json", "r"))
                        try:
                            passphrase1 = input("Passphrase : ")
                            public_key = RSA.importkey(recovery["public_key"])
                            sign = PKCS1_v1_5.new(public_key)
                            dig = sha512(recovery["data"])
                            dig.update(b64decode(recovery["data"]))
                            if(sign.verify(dig, b64decode(recovery["signature"]))):
                                print("Success! Prompting to Main Menu...")
                                sleep(3)
                                self.main_menu()
                            else:
                                print("Verification process failed. Please try again!")
                                sleep(3)
                                self.setup()
                        except:
                            print("Error. Wrong password ! ")
                            sleep(3)
                            self.setup()

        else:self.main_menu()

                        
                
if(__name__ == "__main__"):
    main().setup()