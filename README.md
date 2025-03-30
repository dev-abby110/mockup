# VidwanCheck - Blockchain Certificate Verification System

VidwanCheck is a modern, secure, and user-friendly blockchain-based certificate verification system. It allows institutions to issue tamper-proof digital certificates and enables anyone to instantly verify their authenticity using QR codes.


## 🌟 Features

- *Blockchain-Powered Verification*: Utilizes Ethereum blockchain for immutable certificate storage
- *QR Code Integration*: Quick verification through scannable QR codes
- *User-Friendly Interface*: Modern, responsive design with smooth animations
- *Secure Admin Panel*: Protected administrative access for certificate issuance
- *Instant Verification*: Real-time certificate validation
- *MongoDB Integration*: Secure storage for administrative data
- *Download Certificates*: Easy QR code download functionality

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Node.js and npm
- MongoDB
- Ganache (for local blockchain)
- MetaMask (for blockchain interaction)

### Installation

1. Clone the repository:
   bash
   git clone https://github.com/yourusername/blockchain-certification.git
   cd blockchain-certification
   

2. Install Python dependencies:
   bash
   pip install -r requirements.txt
   

3. Install Truffle and project dependencies:
   bash
   npm install -g truffle
   npm install
   

4. Start Ganache and configure truffle-config.js with your network settings

5. Deploy smart contracts:
   bash
   truffle migrate --reset
   

6. Start MongoDB service

7. Run the application:
   bash
   python app.py
   

## 💻 Usage

### For Institutions (Admins)

1. Access the admin panel through /login-admin
2. Login with your credentials
3. Fill in certificate details:
   - Awardee Name
   - Certificate Name
   - Certificate ID
4. Generate and issue the certificate
5. Download the QR code for distribution

### For Certificate Verification

1. Visit the homepage
2. Click "Verify Certificate"
3. Either:
   - Scan the QR code using your device's camera
   - Manually enter the certificate hash
4. View verification results instantly

## 🏗 Project Structure


blockchain-certification/
├── app.py              # Flask application main file
├── contracts/          # Ethereum smart contracts
├── migrations/         # Truffle migration files
├── static/            # Static assets (CSS, JS, images)
├── templates/         # HTML templates
├── test/             # Smart contract tests
└── truffle-config.js  # Truffle configuration


## 🔒 Security Features

- Blockchain-based immutable records
- Secure admin authentication
- MongoDB for secure data storage
- Protected API endpoints
- Input validation and sanitization

## 🛠 Technology Stack

- *Frontend*: HTML5, CSS3, JavaScript
- *Backend*: Flask (Python)
- *Blockchain*: Ethereum (Solidity)
- *Database*: MongoDB
- *Development Tools*: Truffle, Ganache
- *Libraries*: Web3.py, QRCode

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

For any queries or support, please contact:
- Email: info@vidwancheck.com
- Phone: +91 1234567890

---

Made with ❤ by VidwanCheck Team