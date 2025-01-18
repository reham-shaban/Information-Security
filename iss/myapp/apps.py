import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import NameOID, CertificateBuilder, CertificateSigningRequestBuilder
from cryptography import x509
import datetime
from django.apps import AppConfig
from iss import settings

class YourAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myapp'

    def ready(self):
        try:
            # Paths for the server and CA files
            ca_key_path = getattr(settings, "CA_KEY_PATH", "ca_key.pem")
            ca_cert_path = getattr(settings, "CA_CERT_PATH", "ca_cert.pem")
            ca_public_key_path = getattr(settings, "CA_PUBLIC_KEY_PATH", "ca_public_key.pem")

            server_cert_path = getattr(settings, "SERVER_CERT_PATH", "server_cert.pem")

            server_signing_key_path = getattr(settings, "SERVER_SIGNING_KEY_PATH", "server_signing_key.pem")
            server_signing_public_key_path = getattr(settings, "SERVER_SIGNING_PUBLIC_KEY_PATH", "server_signing_public_key.pem")
            
            server_encryption_key_path = getattr(settings, "SERVER_ENCRYPTION_KEY_PATH", "server_encryption_key.pem")
            server_encryption_public_key_path = getattr(settings, "SERVER_ENCRYPTION_PUBLIC_KEY_PATH", "server_encryption_public_key.pem")

            # Ensure CA files exist before proceeding
            if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
                print("[DEBUG] Generating CA key and certificate...")
                self.generate_ca_certificate(ca_key_path, ca_cert_path, ca_public_key_path)

            # Only generate the server certificate if it doesn't already exist
            if not os.path.exists(server_cert_path):
                self.generate_server_certificate(
                    ca_key_path, ca_cert_path,
                    server_signing_key_path, server_signing_public_key_path,
                    server_encryption_key_path, server_encryption_public_key_path,
                    server_cert_path
                )

        except Exception as e:
            print(f"[ERROR] Error during certificate generation: {e}")

    def generate_ca_certificate(self, ca_key_path, ca_cert_path, ca_public_key_path):
        try:
            print("[DEBUG] Generating CA private key...")
            ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            self.save_pem_file(ca_key_path, ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ), "CA private key")

            print("[DEBUG] Generating CA self-signed certificate...")
            ca_cert = CertificateBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SY"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Damascus"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Damascus"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Gov Server"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"Root CA"),
                ])
            ).issuer_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SY"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Damascus"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Damascus"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Gov Server"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"Root CA"),
                ])
            ).public_key(
                ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).sign(ca_key, hashes.SHA256())

            self.save_pem_file(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM), "CA certificate")
            self.save_public_key(ca_public_key_path, ca_key.public_key(), "CA public key")

        except Exception as e:
            print(f"[ERROR] Failed to generate CA certificate: {e}")
            raise

    def generate_server_certificate(self, ca_key_path, ca_cert_path, signing_key_path, signing_public_key_path, encryption_key_path, encryption_public_key_path, cert_path):
        try:
            print("[DEBUG] Generating server signing private key...")
            signing_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            print("[DEBUG] Generating server encryption private key...")
            encryption_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            self.save_pem_file(signing_key_path, signing_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ), "server signing private key")

            self.save_public_key(signing_public_key_path, signing_key.public_key(), "server signing public key")

            self.save_pem_file(encryption_key_path, encryption_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ), "server encryption private key")

            self.save_public_key(encryption_public_key_path, encryption_key.public_key(), "server encryption public key")

            print("[DEBUG] Creating CSR...")
            csr = CertificateSigningRequestBuilder().subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"SY"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Damascus"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Damascus"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Gov Server"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"Server"),
                ])
            ).sign(signing_key, hashes.SHA256())

            print("[DEBUG] Loading CA key and certificate...")
            ca_key, ca_cert = self.load_ca_files(ca_key_path, ca_cert_path)

            print("[DEBUG] Signing server certificate...")
            server_cert = CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(ca_key, hashes.SHA256())

            self.save_pem_file(cert_path, server_cert.public_bytes(serialization.Encoding.PEM), "server certificate")

        except Exception as e:
            print(f"[ERROR] Failed to generate server certificate: {e}")
            raise

    def load_ca_files(self, ca_key_path, ca_cert_path):
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    def save_pem_file(self, path, content, file_description):
        print(f"[DEBUG] Saving {file_description} to {path}...")
        with open(path, "wb") as f:
            f.write(content)
        print(f"[DEBUG] {file_description.capitalize()} saved successfully.")

    def save_public_key(self, path, public_key, file_description):
        print(f"[DEBUG] Saving {file_description} to {path}...")
        with open(path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[DEBUG] {file_description.capitalize()} saved successfully.")
