from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class CryptographyHandler:
    '''
    This class provides encryption, decryption, signing and verification
    of messages using RSA asymmetric cryptography.
    '''
    def __init__(self, private_key_file, public_key_file):
        self.private_key = self.load_private_key(private_key_file)
        self.public_key = self.load_public_key(public_key_file)

    def load_private_key(self, private_key_file):
        # Load private key from file in PEM format
        with open(private_key_file, 'rb') as f:
            private_key_pem = f.read()
        return serialization.load_pem_private_key(
            private_key_pem,
            password=b'081290a0e436f30e02c420ce62821b43d865e74bddc04a48e345eb1f01c6e2d4'
        )

    def load_public_key(self, public_key_file):
        # Load public key from file in PEM format
        with open(public_key_file, 'rb') as f:
            public_key_pem = f.read()
        return serialization.load_pem_public_key(public_key_pem)

    def encrypt_message(self, message_data):
        # Encrypt message using public key
        ciphertext = self.public_key.encrypt(
            message_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_message(self, ciphertext):
        # Decrypt message using private key
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def sign_message(self, message_sign):
        # Sign message using private key
        signature = self.private_key.sign(
            message_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, signature, message_sign):
        # Verify signature using public key
        try:
            self.public_key.verify(
                signature,
                message_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f'Signature verification failed: {e}')
            return False

if __name__ == "__main__":
    crypto_handler = CryptographyHandler('RSAPrivateKey.pem', 'RSAPublicKey.pem')

    # Encrypting
    message_data = b'This is a secure message!'
    ciphertext = crypto_handler.encrypt_message(message_data)
    print(f'Plaintext: {message_data.decode()}')
    print(f'Ciphertext: {ciphertext.hex()}')

    # Decrypting
    decrypted_data = crypto_handler.decrypt_message(ciphertext)
    print(f'Decrypted data: {decrypted_data.decode()}')

    # Signing
    message_sign = b'8c747032a1aa5af580f48ad2be75366bb517fe8b0990d10931eda23795f3cf26'
    signature = crypto_handler.sign_message(message_sign)

    # Verifying
    if crypto_handler.verify_signature(signature, message_sign):
        print('Signature valid :) Your data is trusted.')
    else:
        print('Signature invalid :( Your data is not trusted.')
