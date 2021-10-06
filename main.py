from flask import Flask, request, Response, jsonify
from json import load, dump, dumps
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import string
import requests
import concurrent.futures
from hashlib import sha512
from Crypto import Random
from base64 import b64decode
from ast import literal_eval
from os import stat
app = Flask(__name__)
req = requests.Session()


#CrazyCoin Source Code

# Punish fraudlent Nodes on Proof Of Stake
# Have to find a way to check Ownership of wallet

class API():
    def __init__(self):
        self.block = load(open("block_list.json", 'r'))
        try:
            self.block_number = self.block["latest_block"],
        except:
            self.block_number = ""
        self.wallets = load(open("wallets.json", 'r')),
        self.settings = load(open("settings.json", "r"))

    def dump_transaction_list(self):
        dump(self.transaction_list, open("transaction_list.json", 'w'))
        return True

    def dump_blockchain(self):
        dump(self.block, open("block_list.json", "w"))
        return True

    def dump_settings(self):
        dump(self.settings, open("settings.json", 'w'))
        return True

    def check_nodes(self):
        num = 0
        for worker in open("workers.txt", 'r').readlines():
            num = num + 1
        return num

    def get_wallet_value(self, address):
        try:
            if(not self.wallets[address]):
                return self.wallets[address]
            else:
                return 0
        except:
            return 0

    def verify_wallet(self, wallet_addr, content, signature):
        public_key = RSA.importkey(wallet_addr)
        sign = PKCS1_v1_5.new(public_key)
        dig = sha512(content)
        dig.update(b64decode(str(content)))
        if(sign.verify(dig, b64decode(signature))):
            return True
        else:
            return False


    def proof_of_stake_verify(self):
        if self.block[self.block_number][0]["confirmations"] == 1:
            conf_hash = req.post(self.block[self.block_number][0]["confirmation_workers"][0]["1"] + "/data", data={"token": open("temporary.txt", 'r').readline()})
            if conf_hash == 200:
                conf_hash_json = conf_hash.json()
                if conf_hash_json["hash"] == self.block[self.block_number][0]["hashes"][0]["1"]:
                    pass
                else:self.block[self.block_number] = ""

            elif self.block[self.block_number][0]["confirmations"] == 2:
                conf_hash = req.post(self.block[self.block_number][0]["confirmation_workers"][0]["2"] + "/data", data={"token": open("temporary.txt", 'r').readline()})
                if conf_hash == 200:
                    conf_hash_json = conf_hash.json()
                    if conf_hash_json["hash"] == self.block[self.block_number][0]["hashes"][0]["2"]:
                        pass
                    else:self.block[self.block_number] = ""

            elif self.block[self.block_number][0]["confirmations"] == 3:
                conf_hash = req.post(self.block[self.block_number][0]["confirmation_workers"][0]["3"] + "/data", data={"token": open("temporary.txt", 'r').readline()})
                if conf_hash == 200:
                    conf_hash_json = conf_hash.json()
                    if conf_hash_json["hash"] == self.block[self.block_number][0]["hashes"][0]["3"]:
                        pass
                    else:self.block[self.block_number][0] = ""

            elif self.block[self.block_number][0]["confirmations"] == 4:
                conf_hash = req.post(self.block[self.block_number][0]["confirmation_workers"][0]["4"] + "/data", data={"token": open("temporary.txt", 'r').readline()})
                if conf_hash == 200:
                    conf_hash_json = conf_hash.json()
                    if conf_hash_json["hash"] == self.block[self.block_number][0]["hashes"][0]["4"]:
                        pass
                    else:self.block[self.block_number][0] = ""

            elif self.block[self.block_number][0]["confirmations"] == 5:
                conf_hash = req.post(self.block[self.block_number][0]["confirmation_workers"][0]["5"] + "/data", data={"token": open("temporary.txt", 'r').readline()})
                if conf_hash == 200:
                    conf_hash_json = conf_hash.json()
                    if conf_hash_json["hash"] == self.block[self.block_number][0]["hashes"][0]["5"]:
                        pass
                    else:self.block[self.block_number][0] = ""

        self.dump_blockchain()
    
    def nodes_send_task(self, address, signature, message, public_key):
        negative_confirmations = 0
        worker_num = 0
        random_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(500)) # This token is used as one-time verification of being the main server to verify the nodes in proof_of_stake_verify().
        open("temporary.txt", 'w').write(random_token)
        for worker in open("workers.txt", 'r').readlines():
            if not worker:
                worker_num += 1
                hash_ = dump({})
                try:
                    task_response = req.post(worker + "/recieve_task", data={"signature" : signature, "message" : message, "public_key" : public_key, "reciever" : self.block[self.block_number][0]["reciever"],"hashes" : dumps(hash_()), "temporary_token" : random_token}) # Should change the public key to the sender address
                    task_response_json = task_response.json()
                    if task_response_json["success"] == False:
                        negative_confirmations += 1
                        if stat("failed_workers.txt").st_size != 0:
                            open("failed_workers.txt", 'a').write('\n' + task_response.raw._fp.fp_sock_getpeername())
                        else:open("failed_workers.txt", 'a').write(task_response.raw._fp.fp_sock_getpeername())
                except:pass
                if task_response_json["success"] == True:
                    if worker_num == 5 and negative_confirmations < 3:
                        self.block[self.block_number[0]["hashes"][0]["hash5"]] = sha512(task_response["hash"]).hexdigest()
                        self.block[self.block_number][0]["confirmation_workers"][0]["5"] = worker
                        return dumps({"success" : True, "negative confirms" : negative_confirmations})
                    elif worker_num < 5:
                        self.block[self.block_number][0]["confirmations"] += 1
                        if self.block[self.block_number][0]["confirmations"] == 1:
                            self.block[self.block_number[0]["hashes"][0]["hash1"]] = sha512(task_response["hash"]).hexdigest()
                            self.block[self.block_number][0]["confirmation_workers"][0]["1"] = worker
                        elif self.block[self.block_number][0]["confirmations"] == 2:
                            self.block[self.block_number[0]["hashes"][0]["hash2"]] = sha512(task_response["hash"]).hexdigest()
                            self.block[self.block_number][0]["confirmation_workers"][0]["2"] = worker
                        elif self.block[self.block_number][0]["confirmations"] == 3:
                            self.block[self.block_number[0]["hashes"][0]["hash3"]] = sha512(task_response["hash"]).hexdigest()
                            self.block[self.block_number][0]["confirmation_workers"][0]["3"] = worker
                        elif self.block[self.block_number][0]["confirmations"] == 4:
                            self.block[self.block_number[0]["hashes"][0]["hash4"]] = sha512(task_response["hash"]).hexdigest()
                            self.block[self.block_number][0]["confirmation_workers"][0]["4"] = worker

                    else:return False
                else:
                    if negative_confirmations < 3:
                        pass
                    else:
                        self.block[self.block_number][0]["rejected"] = True
        self.dump_blockchain()
  

        
    def create_block(self, sender, reciever, sender_private_key, amount, signature, public_key, content):
        exec_ = concurrent.futures.Executor()
        for hash_ in open("hashes.txt", 'r').readlines():
                try:
                   for block in open("block_list.json", 'r'.readlines()):
                        if isinstance(self.block[block][0]["reciever_amount"], int) or isinstance(self.block[block][0]["sender_amount"]):
                            self.proof_of_stake_verify()
                            confirmations = exec.submit(self.nodes_send_task()).result()
                            if confirmations.result()["success"] == True:
                                if isinstance(self.transaction_list[sender], int):
                                    if self.wallets[sender] >= amount:
                                        for block in self.blockchain:
                                            if self.blockchain[block][0]["sender"] == sender and self.verify_wallet(sender, content, signature) != False:
                                                     # Have to add a special way to award workers
                                                self.block_number = self.block_number + 1
                                                self.block["block" + self.block_number][0]["number"] = self.block_number
                                                self.block["block" + self.block_number][0]["transaction_id"] = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(20))
                                                self.block["block" + self.block_number][0]["sender"] = sender
                                                self.block["block" + self.block_number][0]["reciever"] = reciever
                                                self.block["block" + self.block_number][0]["amount"] = amount - 0.0001
                                                self.block["block" + self.block_number][0]["confirmations"] = 0
                                                self.block["block" + self.block_number][0]["sender_amount"] = self.wallets[sender] - amount
                                                self.block["block" + self.block_number][0]["sender_signature"] = signature
                                                try:
                                                    self.block["block" + self.block_number][0]["reciever_amount"] = int(self.block["block" + self.block_number][0]["reciever_amount"]) + amount
                                                except:
                                                    self.block["block" + self.block_number][0]["reciever_amount"] = amount
                                                self.wallets[reciever] = amount
                                                confirmations = exec_.submit(self.nodes_send_task(reciever, signature, public_key))
                                                if self.block[self.block_number][0]["confirmations"] <3:
                                                    for worker in open("failed_workers.txt", 'r').readlines():
                                                        addr = req.get(worker + "/address")
                                                        addr_json = addr.json()
                                                        send_data_ = req.get(worker + "/change", data={"token" : open("temporary.txt", 'r').readline(), "blockchain" : dumps(self.block)})
                                                        #Check here
                                                        amount_ = exec_.submit(self.check_nodes()).result() / self.block_number # Probably will add later punishment for wrong nodes
                                                        exec_.submit(self.create_block("reward", addr_json["address"], ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(20)), amount)) # Change wallet starting point
                                                else:
                                                    for worker in open("workers.txt", 'r').readlines():
                                                        addr = req.get(worker + "/address")
                                                        addr_json = addr.json()
                                                        amount_ = exec_.submit(self.check_nodes()).result() / self.block_number
                                                        exec_.submit(self.create_block("reward", addr_json["address"], ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(20)), amount))         
                                                        # Send task to worker
                                                # Have to add all 3 confirmation-nodes for every confirmation
                                                self.proof_of_stake_verify()
                                                self.block["block" + self.block_number][0]["sender_balance"] = self.transaction_list[sender]
                                                self.transaction_list[sender] = amount
                                                self.dump_transaction_list()
                                                return{"status" : 200, "amount" : amount, "sender" : sender, "reciever": reciever, "block_hash" : hash}
                                            else:pass
                                        return False
                                else:return False
                            else:return False
                        else:pass

                except:
                    return False
                # Added own version of proof of stake protocol

        self.dump_blockchain()

    def retrieve_blockchain(self):
        return dumps(open("block_list.json", 'r').read())

    def retrieve_wallets(self):
        return dumps(open("wallets.json", 'r').read())

    def main(self):
        if(self.settings["setup"] == False):
            amount = input("Creating owner account...\nHow much Coins do you want to be available in the network? ")
            addr = input("Address to send : ")
            if("block" + self.block_number == {}):
                self.block["latest_block"] = 1
                self.block_number = self.block["latest_block"]
                self.block["block1"][0]["sender"] = "blockchain"
                self.block["block1"][0]["reciever"] = addr
                self.block["block1"][0]["sender_signature"] = "self-signed"
                self.block["block1"][0]["content"] = "self-signed"
                self.block["block1"][0]["amount"] = amount
                self.block["block1"][0]["block_hash"] = "self-signed"
                self.block["block1"][0]["sender_amount"] = amount
                self.settings["setup"] = True
                self.dump_blockchain()
                
            else:
                print("Manupulation found! Flushing blocklist file..")
                empty_json = dump({}, open("block_list.json", "w"))
                self.settings["setup"] = False
                self.dump_settings()
                self.main()
            print("Success!")

            
        @app.route("/send", methods=["POST"])
        def response0():
            try:
                exec_ = concurrent.futures.Executor()
                transaction_ = exec_.submit(self.create_block(request.json["sender"], request.json["reciever"], request.json["amount"], request.json["content"]))
                if transaction_.result == True:
                    return Response(status=200)
                else:return Response(status=403)
            except:return Response(status=403)


        @app.route("/blockchain", methods=["GET"])
        def response1():
            return jsonify({"blockchain" : self.retrieve_blockchain(), "wallets" : self.retrieve_wallets(), "status" : 200})


        @app.route("/wallet", methods=["POST"])
        def response2():
            if(not request.json["wallet"]):
                return jsonify({"value" : API().get_wallet_value(request.json["wallet"]), "status" : 200})
            else: 
                return jsonify({"error" : "No address specified", "status" : 404})
        


        app.run("0.0.0.0", debug=True)


        
if(__name__ == "__main__"):
    API().main()
        
