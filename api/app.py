import os
import json
import random
from web3 import Web3
import ipfsapi
import ipfshttpclient
import hashlib
from flask import Flask, render_template, redirect, request
from forms import registrationForm, authenticationForm, peerForm, taForm, transferOwnerForm, checkOwnerForm
from werkzeug.utils import  secure_filename
from eth_utils import keccak, to_checksum_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['UPLOAD_FOLDER'] = 'static/files'


@app.route('/', methods=['GET','POST'])
def base():

    client = ipfsapi.Client('127.0.0.1', 5001)

    node_url = 'HTTP://127.0.0.1:8545'
    # node_url = 'https://mainnet.infura.io/v3/1581fb4fc2b94cc1bc14a032876e462f'
    w3 = Web3(Web3.HTTPProvider(node_url))
    connection = w3.is_connected()
    print("Connection to blockchain: " + str(connection))
    default_account_address = w3.eth.accounts[0]


    # smart Contract
    byte_code = '608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550604051806040016040528060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600160038111156100ac576100ab61018e565b5b815250600160008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160000160146101000a81548160ff021916908360038111156101815761018061018e565b5b02179055509050506101bd565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b611bd780620001cd6000396000f3fe6080604052600436106100955760003560e01c80636d435421116100595780636d435421146101b35780639d95f1cc146101dc578063bb4ab6b414610205578063e7977dc014610242578063f3d6fc391461027f5761009c565b80630c8b234e146100aa5780632e9b50bd146100e757806333a9f2b6146101105780633fc69d47146101395780634869fe26146101765761009c565b3661009c57005b3480156100a857600080fd5b005b3480156100b657600080fd5b506100d160048036038101906100cc91906112d2565b6102aa565b6040516100de919061130e565b60405180910390f35b3480156100f357600080fd5b5061010e600480360381019061010991906112d2565b610316565b005b34801561011c57600080fd5b506101376004803603810190610132919061135f565b6104b7565b005b34801561014557600080fd5b50610160600480360381019061015b91906112d2565b61078e565b60405161016d919061147b565b60405180910390f35b34801561018257600080fd5b5061019d600480360381019061019891906112d2565b610878565b6040516101aa9190611595565b60405180910390f35b3480156101bf57600080fd5b506101da60048036038101906101d591906115b7565b610a0b565b005b3480156101e857600080fd5b5061020360048036038101906101fe91906112d2565b610c32565b005b34801561021157600080fd5b5061022c600480360381019061022791906115f7565b610dd4565b6040516102399190611675565b60405180910390f35b34801561024e57600080fd5b50610269600480360381019061026491906115f7565b610e53565b604051610276919061169f565b60405180910390f35b34801561028b57600080fd5b50610294611085565b6040516102a1919061147b565b60405180910390f35b6000600260008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b60006103213361116d565b905060016003811115610337576103366113d5565b5b81600381111561034a576103496113d5565b5b1415801561037d575060026003811115610367576103666113d5565b5b81600381111561037a576103796113d5565b5b14155b156103bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103b49061173d565b60405180910390fd5b60405180604001604052808373ffffffffffffffffffffffffffffffffffffffff1681526020016003808111156103f7576103f66113d5565b5b815250600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160000160146101000a81548160ff021916908360038111156104ab576104aa6113d5565b5b02179055509050505050565b60006104c23361116d565b9050600160038111156104d8576104d76113d5565b5b8160038111156104eb576104ea6113d5565b5b1415801561051e575060026003811115610508576105076113d5565b5b81600381111561051b5761051a6113d5565b5b14155b1561055e576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610555906117cf565b60405180910390fd5b6000600260008773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000209050600073ffffffffffffffffffffffffffffffffffffffff168160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610634576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161062b9061183b565b60405180910390fd5b858160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550848160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555080600201859080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600360008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000868152602001908152602001600020905084816000018190555083816001018190555050505050505050565b6107966111c6565b600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206040518060400160405290816000820160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020016000820160149054906101000a900460ff16600381111561085b5761085a6113d5565b5b600381111561086d5761086c6113d5565b5b815250509050919050565b610880611208565b600260008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206040518060600160405290816000820160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020016001820160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001600282018054806020026020016040519081016040528092919081815260200182805480156109fb57602002820191906000526020600020905b8160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190600101908083116109b1575b5050505050815250509050919050565b6000610a163361116d565b905060006003811115610a2c57610a2b6113d5565b5b816003811115610a3f57610a3e6113d5565b5b1480610a6e5750600380811115610a5957610a586113d5565b5b816003811115610a6c57610a6b6113d5565b5b145b15610aae576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610aa5906118cd565b60405180910390fd5b6000600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000209050600073ffffffffffffffffffffffffffffffffffffffff168160000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1603610b84576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b7b90611939565b60405180910390fd5b828160010160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555080600201839080600181540180825580915050600190039060005260206000200160009091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050505050565b6000610c3d3361116d565b905060016003811115610c5357610c526113d5565b5b816003811115610c6657610c656113d5565b5b14158015610c99575060026003811115610c8357610c826113d5565b5b816003811115610c9657610c956113d5565b5b14155b15610cd9576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610cd0906119cb565b60405180910390fd5b60405180604001604052808373ffffffffffffffffffffffffffffffffffffffff16815260200160026003811115610d1457610d136113d5565b5b815250600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008201518160000160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060208201518160000160146101000a81548160ff02191690836003811115610dc857610dc76113d5565b5b02179055509050505050565b610ddc611255565b600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600083815260200190815260200160002060405180604001604052908160008201548152602001600182015481525050905092915050565b6000806003811115610e6857610e676113d5565b5b610e713361116d565b6003811115610e8357610e826113d5565b5b03610ec3576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610eba90611a5d565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1603610f94576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f8b90611ac9565b60405180910390fd5b81600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008481526020019081526020016000206000015414611029576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161102090611b81565b60405180910390fd5b600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600083815260200190815260200160002060010154905092915050565b61108d6111c6565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206040518060400160405290816000820160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020016000820160149054906101000a900460ff166003811115611152576111516113d5565b5b6003811115611164576111636113d5565b5b81525050905090565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000160149054906101000a900460ff169050919050565b6040518060400160405280600073ffffffffffffffffffffffffffffffffffffffff16815260200160006003811115611202576112016113d5565b5b81525090565b6040518060600160405280600073ffffffffffffffffffffffffffffffffffffffff168152602001600073ffffffffffffffffffffffffffffffffffffffff168152602001606081525090565b604051806040016040528060008152602001600081525090565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061129f82611274565b9050919050565b6112af81611294565b81146112ba57600080fd5b50565b6000813590506112cc816112a6565b92915050565b6000602082840312156112e8576112e761126f565b5b60006112f6848285016112bd565b91505092915050565b61130881611294565b82525050565b600060208201905061132360008301846112ff565b92915050565b6000819050919050565b61133c81611329565b811461134757600080fd5b50565b60008135905061135981611333565b92915050565b600080600080608085870312156113795761137861126f565b5b6000611387878288016112bd565b9450506020611398878288016112bd565b93505060406113a98782880161134a565b92505060606113ba8782880161134a565b91505092959194509250565b6113cf81611294565b82525050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b60048110611415576114146113d5565b5b50565b600081905061142682611404565b919050565b600061143682611418565b9050919050565b6114468161142b565b82525050565b60408201600082015161146260008501826113c6565b506020820151611475602085018261143d565b50505050565b6000604082019050611490600083018461144c565b92915050565b600081519050919050565b600082825260208201905092915050565b6000819050602082019050919050565b60006114ce83836113c6565b60208301905092915050565b6000602082019050919050565b60006114f282611496565b6114fc81856114a1565b9350611507836114b2565b8060005b8381101561153857815161151f88826114c2565b975061152a836114da565b92505060018101905061150b565b5085935050505092915050565b600060608301600083015161155d60008601826113c6565b50602083015161157060208601826113c6565b506040830151848203604086015261158882826114e7565b9150508091505092915050565b600060208201905081810360008301526115af8184611545565b905092915050565b600080604083850312156115ce576115cd61126f565b5b60006115dc858286016112bd565b92505060206115ed858286016112bd565b9150509250929050565b6000806040838503121561160e5761160d61126f565b5b600061161c858286016112bd565b925050602061162d8582860161134a565b9150509250929050565b61164081611329565b82525050565b60408201600082015161165c6000850182611637565b50602082015161166f6020850182611637565b50505050565b600060408201905061168a6000830184611646565b92915050565b61169981611329565b82525050565b60006020820190506116b46000830184611690565b92915050565b600082825260208201905092915050565b7f53656e64657220646f65736e27742068617665207065726d697373696f6e207460008201527f6f206164642050656572204e6f64652e00000000000000000000000000000000602082015250565b60006117276030836116ba565b9150611732826116cb565b604082019050919050565b600060208201905081810360008301526117568161171a565b9050919050565b7f53656e64657220646f65736e27742068617665207065726d697373696f6e207460008201527f6f205265676973746572204465766963652e0000000000000000000000000000602082015250565b60006117b96032836116ba565b91506117c48261175d565b604082019050919050565b600060208201905081810360008301526117e8816117ac565b9050919050565b7f44657669636520494420616c7265616479206578697374732e00000000000000600082015250565b60006118256019836116ba565b9150611830826117ef565b602082019050919050565b6000602082019050818103600083015261185481611818565b9050919050565b7f596f7520646f6e27742068617665207065726d697373696f6e20746f2074726160008201527f6e73666572206f776e6572736869702e00000000000000000000000000000000602082015250565b60006118b76030836116ba565b91506118c28261185b565b604082019050919050565b600060208201905081810360008301526118e6816118aa565b9050919050565b7f446576696365204944206e6f7420666f756e642e000000000000000000000000600082015250565b60006119236014836116ba565b915061192e826118ed565b602082019050919050565b6000602082019050818103600083015261195281611916565b9050919050565b7f53656e64657220646f65736e27742068617665207065726d697373696f6e207460008201527f6f20616464205441204e6f64652e000000000000000000000000000000000000602082015250565b60006119b5602e836116ba565b91506119c082611959565b604082019050919050565b600060208201905081810360008301526119e4816119a8565b9050919050565b7f53656e64657220646f65736e27742068617665207065726d697373696f6e207460008201527f6f2041757468656e74696361746520746865204465766963652e000000000000602082015250565b6000611a47603a836116ba565b9150611a52826119eb565b604082019050919050565b60006020820190508181036000830152611a7681611a3a565b9050919050565b7f44657669636520446f6573206e6f742065786974000000000000000000000000600082015250565b6000611ab36014836116ba565b9150611abe82611a7d565b602082019050919050565b60006020820190508181036000830152611ae281611aa6565b9050919050565b7f4368616c6c656e676520526573706f6e7365205061697220666f72207468697360008201527f2044657669636520646f6573206e6f74206578697374732e204465766963652060208201527f63616e6e6f742062652061757468656e74696361746564000000000000000000604082015250565b6000611b6b6057836116ba565b9150611b7682611ae9565b606082019050919050565b60006020820190508181036000830152611b9a81611b5e565b905091905056fea264697066735822122090427fbcc651c56465ee14d02fa1a6994b16ec7953b569fef89b0d88d00d55d464736f6c63430008120033'
    abi = json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"stateMutability":"nonpayable","type":"fallback"},{"inputs":[{"internalType":"address","name":"tanode","type":"address"}],"name":"addNode","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"peer","type":"address"}],"name":"addPeer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"},{"internalType":"uint256","name":"chalHash","type":"uint256"}],"name":"authenticateDevice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"}],"name":"checkOwnership","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"}],"name":"getipfschalCID","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"}],"name":"getipfsrespCID","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"},{"internalType":"address","name":"owner","type":"address"},{"internalType":"uint256","name":"chalHash","type":"uint256"},{"internalType":"uint256","name":"respHash","type":"uint256"}],"name":"registerDevice","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"},{"internalType":"string","name":"ipfschalCID","type":"string"},{"internalType":"string","name":"ipfsrespCID","type":"string"}],"name":"storeIPFS","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"deviceId","type":"address"},{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]')
    obj = w3.eth.contract(abi=abi, bytecode=byte_code)
    tx_hash = obj.constructor().transact({'from': default_account_address})
    # # # contract = w3.eth.contract(address= contract_address, abi= abi)
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract_address = tx_receipt.contractAddress
    deployed_contract = w3.eth.contract(address=contract_address, abi=abi)
    print("Deployed Contract: " + str(deployed_contract))

    # Adding some default TA nodes
    TANodes = []
    for i in range(2):
        TANodes.append(w3.eth.accounts[i+1])
    # x = deployed_contract.functions.ownerAddress().call()
    print("TA NODE [ ] : ")
    for i in TANodes:
        tx_hash = deployed_contract.functions.addNode(i).transact({'from': default_account_address})
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(w3.to_hex(tx_hash))

    # Default peer node registration
    peerNodes = []
    for i in range(2):
        peerNodes.append(w3.eth.accounts[i+6])
    print("Peer NODE [ ] : ")
    for i in peerNodes:
        tx_hash = deployed_contract.functions.addPeer(i).transact({'from': default_account_address})
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(w3.to_hex(tx_hash))

    form0 = peerForm()
    form1 = taForm()
    form2 = registrationForm()
    form3 = authenticationForm()
    form4 = transferOwnerForm()
    form5 = checkOwnerForm()

    # if form0.is_submitted():
    #     peer_address = form0.peer_address.data
    #     sender_address = form0.sender_address.data
    #     tx_hash = deployed_contract.functions.addPeer(peer_address).transact({'from': sender_address})
    #     w3.eth.wait_for_transaction_receipt(tx_hash)
    #     message = "Peer Node is Added ."
    #     return render_template("result.html",tx_hash = w3.to_hex(tx_hash),message= message)
    #
    # elif form1.is_submitted():
    #     TA_address = form1.TA_address.data
    #     sender_address = form1.sender_address.data
    #     tx_hash = deployed_contract.functions.addNode(TA_address).transact({'from': sender_address})
    #     w3.eth.wait_for_transaction_receipt(tx_hash)
    #     message = "TA Node is Added ."
    #     return render_template("result.html", tx_hash=w3.to_hex(tx_hash), message=message)
    #
    if form2.is_submitted():
        device_id = form2.device_id.data

        device_id_bytes = device_id.encode() if isinstance(device_id, str) else device_id
        device_id_hash = keccak(device_id_bytes)
        address_bytes = device_id_hash[-20:]  # Extract the last 20 bytes
        device_id = to_checksum_address(address_bytes)

        owner = form2.owner.data
        chal_file = form2.chal_file_dir.data
        chal_file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(chal_file.filename)))
        resp_file = form2.resp_file_dir.data
        resp_file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(resp_file.filename)))
        sender_address = form2.sender_address.data

        hashed_chal_file = open('static/files/'+str(device_id) + '_hashed_chal.txt', "w")
        hashed_resp_file = open('static/files/'+str(device_id) + '_hashed_resp.txt', "w")
        chal_count = 0
        x_chal = []
        x_resp = []
        with open('static/files/'+secure_filename(chal_file.filename), "rt") as f, open('static/files/' + secure_filename(resp_file.filename), "rt") as f2:
            for x, y in zip(f, f2):
                chal_hash = hashlib.sha256(x.strip()[3:].encode('utf-8'))
                chal_hash = int.from_bytes(chal_hash.digest(), byteorder='big')
                x_chal.append(chal_hash)
                resp_hash = hashlib.sha256(y.strip()[9:].encode('utf-8'))
                resp_hash = int.from_bytes(resp_hash.digest(), byteorder='big')
                x_resp.append(resp_hash)
                hashed_chal_file.write(str(chal_hash))
                hashed_resp_file.write(str(resp_hash))
                chal_count = chal_count + 1
        print(os.path.basename(hashed_chal_file.name))

        f.close()
        f2.close()
        hashed_chal_file.close()
        hashed_resp_file.close()

        ipfschalCID = None
        ipfsrespCID = None
        try:
            res = client.add(hashed_chal_file.name)
            ipfschalCID = res['Hash']

            res = client.add(hashed_resp_file.name)
            ipfsrespCID = res['Hash']
        except Exception as e:
            print("Error storing file on IPFS:", str(e))

        tx_hash = deployed_contract.functions.storeIPFS(device_id,ipfschalCID,ipfsrespCID).transact({'from': sender_address})
        print(w3.to_hex(tx_hash))

        directory = 'static/files'  # Directory path
        # Iterate over all files in the directory and remove them
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):  # Check if the path is a file
                os.remove(file_path)

        message_tx_hash =''
        for i in range(chal_count):
            tx_hash = deployed_contract.functions.registerDevice(device_id, owner, x_chal[i], x_resp[i]).transact({'from': sender_address})
            w3.eth.wait_for_transaction_receipt(tx_hash)
            message_tx_hash = message_tx_hash + w3.to_hex(tx_hash) + "\n"
        message = "IoT Device Registered ."
        return render_template("result.html", tx_hash=message_tx_hash, message=message)

    elif form3.is_submitted():
        device_id = form3.device_id.data

        device_id_bytes = device_id.encode() if isinstance(device_id, str) else device_id
        device_id_hash = keccak(device_id_bytes)
        address_bytes = device_id_hash[-20:]  # Extract the last 20 bytes
        device_id = to_checksum_address(address_bytes)

        count = form3.count.data

        # get IPFS file
        ipfschalCID = deployed_contract.functions.getipfschalCID(device_id).call()
        ipfsrespCID = deployed_contract.functions.getipfsrespCID(device_id).call()
        output_chalfile_path = 'static/files/' + str(device_id) + '_hashed_chal.txt'
        output_respfile_path = 'static/files/' + str(device_id) + '_hashed_resp.txt'
        try:
            client.get(ipfschalCID, output=output_chalfile_path)  # Retrieve the file from IPFS
            client.get(ipfsrespCID, output=output_respfile_path)  # Retrieve the file from IPFS
        except Exception as e:
            print("Error retrieving file from IPFS:", str(e))


        file1_path = 'static/files/' + str(device_id) + '_hashed_chal.txt'  # File 1 path
        file2_path = 'static/files/' + str(device_id) + '_hashed_resp.txt'  # File 2 path

        # Read all lines from File 1
        with open(file1_path, 'r') as file1:
            lines_file1 = file1.readlines()

        # Read all lines from File 2
        with open(file2_path, 'r') as file2:
            lines_file2 = file2.readlines()

        random_lines_file1 = random.sample(lines_file1, count)
        corresponding_lines_file2 = []
        for line_file1 in random_lines_file1:
            line_index = lines_file1.index(line_file1)  # Get the index of the line
            corresponding_line_file2 = lines_file2[line_index]  # Get the corresponding line from File 2
            corresponding_lines_file2.append(corresponding_line_file2)

        # Print the random lines from File 1 and corresponding lines from File 2
        for line_file1, line_file2 in zip(random_lines_file1, corresponding_lines_file2):
            x = line_file1.strip()
            print("File 1 Line:", x)
            smart_contract_resp = deployed_contract.functions.authenticateDevice(device_id, x).call()
            if smart_contract_resp != line_file2.strip():
                message = "IoT Device Authentication FAILED."
                return render_template("result.html", tx_hash=x, message=message)

        directory = 'static/files'
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if os.path.isfile(file_path):  # Check if the path is a file
                os.remove(file_path)

        message = "IoT Device Authentication Successfull."
        return render_template("result.html", tx_hash=w3.to_hex(tx_hash), message=message)

    elif form4.is_submitted():
        device_id = form4.device_id.data

        device_id_bytes = device_id.encode() if isinstance(device_id, str) else device_id
        device_id_hash = keccak(device_id_bytes)
        address_bytes = device_id_hash[-20:]  # Extract the last 20 bytes
        device_id = to_checksum_address(address_bytes)

        owner = form4.owner.data
        sender_address = form4.sender_address.data

        tx_hash = deployed_contract.functions.transferOwnership(device_id, owner).transact({'from': sender_address})
        message = "Ownership transfer completed."
        return render_template("result.html", tx_hash=w3.to_hex(tx_hash), message=message)

    elif form5.is_submitted():
        device_id = form5.device_id.data

        device_id_bytes = device_id.encode() if isinstance(device_id, str) else device_id
        device_id_hash = keccak(device_id_bytes)
        address_bytes = device_id_hash[-20:]  # Extract the last 20 bytes
        device_id = to_checksum_address(address_bytes)

        tx_hash = deployed_contract.functions.checkOwnership(device_id).call()
        message = "Device Owner Address"
        return render_template("result.html", tx_hash=tx_hash, message=message)

    return render_template('index.html',form0=form0,form1=form1,form2=form2,form3=form3,form4=form4,form5=form5,connection=connection,default_account_address = default_account_address, deployed_contract = deployed_contract.address, TA_nodes = TANodes, PA_nodes = peerNodes)

if __name__ == "__main__":
    app.run(port=80,debug=True)
