from flask import Flask, request,Response
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from json import load, dump, loads, loads
from Crypto.Hash import SHA512
import requests
import base64

app = Flask(__name__)
req = requests.Session()

class funcs():
    def __init__(self):
        self.settings = load("settings.json", 'r'),
        self.wallets = load("wallets.json", 'r'),
        self.blockchain = load("block_list.json", 'r'),
        self.block_num  = self.blockchain["latest_block"]

    def dump_blockchain(self):
        dump(self.blockchain, open("block_list.json", 'w'))

    def dump_wallet(self):
        dump(self.wallet, open("wallets.json", 'w'))

    def dump_settings(self):
        dump(self.settings, open(self.settings, open("settings.json")))    

    def check_wallet(self, public_key, signature, message):
        try:
            rsa = RSA.importKey(public_key)
            sign = PKCS1_v1_5.new(rsa)
            dig = base64.b64decode(message)
            if sign.verify(dig, base64.b64decode(signature)):return True
            else:False
        except:False

    def check_block(self):
        # 2 = Last block failed to verify (critical), 1 = failed to verify current transaction, 0 = success
        self.last_block = self.block_num - 1
        if self.check_wallet(self.blockchain[self.last_block][0]["sender"], self.blockchain[self.last_block][0]["signature"], self.blockchain[self.last_block][0]["message"]) == True and self.wallet[self.blockchain[self.last_block][0]["sender"]] >= self.blockchain[self.last_block][0]["amount"]:
            if self.check_wallet(self.blockchain[self.block_num][0]["sender"], self.blockchain[self.block_num][0]["signature"], self.blockchain[self.block_num][0]["message"]) == True and self.wallet[self.blockchain[self.block_num][0]["sender"]] >= self.blockchain[self.block_num][0]["amount"]:
                return 0
            else:return 1
        else:return 2

class setup(funcs):
    def __init__(self):pass

    def main(self):
        print("Installing...")
        block_json = req.get(self.settings["server_ip"] + "/blockchain").json()
        open("block_list.json", "w").write(loads(block_json["blockchain"]))
        open("wallets.json", "w").write(loads(block_json["wallets"]))

class API(funcs):
    def __init__(self):pass

    def main(self):
        @app.route("/address", methods=["GET"])
        def response0():
            if request.remote_addr == self.settings["server_ip"]:
                return jsonify({"address" : self.settings["address"], "status" : 200})
            else:
                return Response(status=403)

        @app.route("/recieve_task", methods=["POST"])
        def response1():
            if request.remote_addr == self.settings["server_ip"]:
                open("token.txt", "w").write(request.json["token"])
                if check_block() != 1 or check_block() !=2:
                    return jsonify({"success" : False})
                elif check_block() == 1:return jsonify({"success" : True, "last_block" : False, "status" : 200})
                else:return jsonify({"success" : True, "last_block" : True, "status" : 200})
            else:return Response(status=403)

        @app.route("/data", methods=["POST"])
        def response2():
            if request.remote_addr == self.settings["server_ip"] and request.json["token"] == open("token.txt", 'r').readline():
                self.blockchain[self.block_num][0]["confirmations"] = request.json["confirmations"]
                self.blockchain[self.block_num][0]["tokens"] = request.json["tokens"]
                self.dump_blockchain()

            else:return Response(status=403)

        @app.route("/change", methods=["GET"])
        def response3():
            if request.remote_addr == self.settings["server_ip"] and request.json["token"] == open("token.txt", 'r').readline():
                open("block_list.json", 'w').write(loads(request.json["blockchain"]))
                return Response(status=200)
            else:
                return Response(status=403)

        app.run("0.0.0.0", debug=True)
