import base64
from io import BytesIO
from flask import Flask, render_template, request, jsonify
import qrcode
from web3 import Web3
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_url_path='/static')

# Connect to Sepolia testnet via Infura (or use Alchemy)
WEB3_PROVIDER = os.getenv('WEB3_PROVIDER', 'https://eth-sepolia.g.alchemy.com/v2/your-api-key')
web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))

# Set contract address from environment variable (this will be your deployed contract address)
contract_address = os.getenv('CONTRACT_ADDRESS', '0x34005CF103E7546451cc9c43357942d12ca78540')

# Your contract ABI
contract_abi = [
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": False,
                "internalType": "string",
                "name": "certificateHash",
                "type": "string"
            }
        ],
        "name": "CertificatePublished",
        "type": "event"
    },
    {
        "inputs": [
            {
                "internalType": "string",
                "name": "",
                "type": "string"
            }
        ],
        "name": "certificates",
        "outputs": [
            {"internalType": "string", "name": "awardeeName", "type": "string"},
            {"internalType": "string", "name": "certificateName", "type": "string"},
            {"internalType": "string", "name": "certificateCode", "type": "string"},
            {"internalType": "string", "name": "certificateHash", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "awardeeName", "type": "string"},
            {"internalType": "string", "name": "certificateName", "type": "string"},
            {"internalType": "string", "name": "certificateCode", "type": "string"},
            {"internalType": "string", "name": "certificateHash", "type": "string"}
        ],
        "name": "publishCertificate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "certificateHash", "type": "string"}
        ],
        "name": "verifyCertificate",
        "outputs": [
            {"internalType": "bool", "name": "", "type": "bool"},
            {
                "components": [
                    {"internalType": "string", "name": "awardeeName", "type": "string"},
                    {"internalType": "string", "name": "certificateName", "type": "string"},
                    {"internalType": "string", "name": "certificateCode", "type": "string"},
                    {"internalType": "string", "name": "certificateHash", "type": "string"},
                    {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
                ],
                "internalType": "tuple",
                "name": "",
                "type": "tuple"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# Create contract instance
contract = web3.eth.contract(address=contract_address, abi=contract_abi)

# Your wallet address that will be used to publish certificates
WALLET_ADDRESS = os.getenv('WALLET_ADDRESS', '0x24af5Ae5400781935b5d26611c671432AE41D098')
PRIVATE_KEY = os.getenv('PRIVATE_KEY', '')  # Your wallet's private key

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify')
def verify():
    return render_template('verify.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login_admin')
def login_admin():
    return render_template('login-admin.html')

@app.route('/admin_login', methods=['POST'])
def admin_login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Invalid input'}), 400

    username = data['username']
    password = data['password']

    if username == "admin" and password == "admin":
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/publish', methods=['POST'])
def publish():
    data = request.get_json()
    
    if not all(key in data for key in ['awardee_name', 'certificate_name', 'certificate_code']):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        # Create certificate hash
        certificate_hash = hashlib.sha256(
            f"{data['awardee_name']}{data['certificate_name']}{data['certificate_code']}".encode()
        ).hexdigest()

        # Build transaction
        nonce = web3.eth.get_transaction_count(WALLET_ADDRESS)
        
        # Get gas price
        gas_price = web3.eth.gas_price

        # Build the transaction
        transaction = contract.functions.publishCertificate(
            data['awardee_name'],
            data['certificate_name'],
            data['certificate_code'],
            certificate_hash
        ).build_transaction({
            'chainId': 11155111,  # Sepolia chain ID
            'gas': 2000000,
            'gasPrice': gas_price,
            'nonce': nonce,
            'from': WALLET_ADDRESS
        })

        # Sign and send transaction
        signed_txn = web3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Wait for transaction receipt
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(certificate_hash)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64
        buffered = BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()

        return jsonify({
            'success': True,
            'certificate_hash': certificate_hash,
            'qr_code': qr_code_base64,
            'transaction_hash': receipt['transactionHash'].hex()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    data = request.get_json()
    certificate_hash = data.get('certificate_hash')
    
    if not certificate_hash:
        return jsonify({'error': 'Certificate hash is required'}), 400

    try:
        # Call the smart contract to verify the certificate
        is_valid, certificate_data = contract.functions.verifyCertificate(certificate_hash).call()
        
        if is_valid:
            certificate = {
                'awardeeName': certificate_data[0],
                'certificateName': certificate_data[1],
                'certificateCode': certificate_data[2],
                'certificateHash': certificate_data[3],
                'timestamp': certificate_data[4]
            }
            return jsonify({
                'valid': True,
                'certificate': certificate
            })
        else:
            return jsonify({
                'valid': False,
                'message': 'Certificate not found'
            })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
