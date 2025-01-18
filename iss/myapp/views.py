from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import LoginView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.views.generic import CreateView, TemplateView
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse_lazy
from cryptography import x509
from .forms import CustomUserCreationForm, CustomAuthenticationForm, DocumentUploadForm
from .models import CustomUser, Document
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views.generic import TemplateView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import Document, CustomUser
from .forms import DocumentUploadForm, DocumentSearchForm
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from django.conf import settings
import os 
from django.http import HttpResponse, Http404
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import pyclamd

import hashlib
import pyclamd
from django.core.exceptions import ValidationError
import shutil

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from django.http import FileResponse, Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from .models import Document

# Create your views here.
# Home View


# Set up logger for debug statements
logger = logging.getLogger(__name__)
# Home View
class HomeView(LoginRequiredMixin, TemplateView):
    template_name_user = 'home_user.html'
    template_name_employee = 'home_employee.html'

    def get_template_names(self):
        if self.request.user.role == 'employee':
            return [self.template_name_employee]
        return [self.template_name_user]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Initialize documents variable
        documents = None

        if self.request.user.role == 'user':
            # Get documents for user
            documents = Document.objects.filter(user=self.request.user)
        else:
            # Handle document search
            if self.request.GET.get('national_number'):
                national_number = self.request.GET.get('national_number')
                try:
                    user = CustomUser.objects.get(national_number=national_number)
                    documents = Document.objects.filter(user=user)
                except CustomUser.DoesNotExist:
                    documents = None
          
        context['documents'] = documents
        context['upload_form'] = DocumentUploadForm()
        context['search_form'] = DocumentSearchForm(self.request.GET)
        return context


class DocumentUploadView(LoginRequiredMixin, CreateView):
    model = Document
    form_class = DocumentUploadForm
    template_name = 'upload_document.html'
    success_url = reverse_lazy('home')  # Redirect to the home page after upload

    def generate_key_pair(self, private_key_path, public_key_path):
        # Generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Save the private key to a file
        with open(private_key_path, 'wb') as pk_file:
            pk_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),  # Add a password if required
                )
            )

        # Save the public key to a file
        public_key = private_key.public_key()
        with open(public_key_path, 'wb') as pub_file:
            pub_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        return private_key, public_key

    def encrypt_file(self, file_object):
        # Generate symmetric key and IV
        symmetric_key = os.urandom(32)  # AES-256 key
        iv = os.urandom(16)  # Initialization Vector (IV)

        # Encrypt file content
        file_data = file_object.read()  # Read file data

        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        encrypted_file_path = f"media/documents/{file_object.name}.enc"
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(iv + encrypted_data)  # Save IV with encrypted data

        # Generate RSA keys
        server_private_key, server_public_key = self.generate_key_pair(settings.SERVER_PRIVATE_KEY, settings.SERVER_PUBLIC_KEY)
        client_private_key, client_public_key = self.generate_key_pair(settings.CLIENT_PRIVATE_KEY, settings.CLIENT_PUBLIC_KEY)

        # Encrypt symmetric key using the generated RSA public key
        encrypted_symmetric_key = server_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_file_path, encrypted_symmetric_key


    def form_valid(self, form):
        #form.instance.user = self.request.user
        # Get the document instance from the form
        document_instance = form.save(commit=False)
        
        # Associate the document with the logged-in user
        document_instance.user = self.request.user

        # Sign the document with a digital signature
        signed_document = self.sign_document(document_instance)
        
        # Attach the signed document to the instance
        document_instance.signed_document = signed_document
        document_instance.save()

        # Log debug information
        print(f"Document uploaded successfully by user {self.request.user.name}.")
        print(f"Document signed with digital signature: {signed_document.hex()}")

        # Encrypt the uploaded file
        uploaded_file = form.cleaned_data['file']  # Access the uploaded file
        encrypted_file_path, encrypted_symmetric_key = self.encrypt_file(
            uploaded_file
        )

        # Decrypt the encrypted file and get the decrypted file path
        decrypted_file_path = decrypt_file(encrypted_file_path, encrypted_symmetric_key, settings.SERVER_PRIVATE_KEY)

        # Delete the encrypted file after decryption
        os.remove(encrypted_file_path)

        return super().form_valid(form)

    def sign_document(self, document_instance):
        """
        Sign the document content using a private key.
        This example uses RSA for the signature.
        """
        private_key = self.load_private_key()

        # For demonstration purposes, we will sign the document's file content
        # You should have a method to retrieve the file content (e.g., from the model's file field)
        document_content = document_instance.file.read()

        print(f"Signing document content: {document_content[:100]}...")  # Log first 100 chars for debug

        # Generate the signature
        signature = private_key.sign(
            document_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Log the signature generation
        print(f"Generated digital signature: {signature.hex()}")
        
        return signature

    def load_private_key(self):
        """
        Load the private key used for signing. You can adjust this part based on how your private key is stored.
        """
        try:
            # For example, load from a PEM file (this file should be securely stored and never exposed)
            with open(settings.SERVER_SIGNING_KEY_PATH, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            print("Private key loaded successfully.")
            return private_key
        except Exception as e:
            print(f"Failed to load private key: {e}")
            raise

# Register
class RegisterView(CreateView):
    model = CustomUser
    form_class = CustomUserCreationForm
    template_name = 'register.html'

    def form_valid(self, form):
        form.save()
        national_number = form.cleaned_data.get('national_number')
        password = form.cleaned_data.get('password')

        # Authenticate using `national_number` as the username
        user = authenticate(request=self.request, national_number=national_number, password=password)

        if user is not None:
            login(self.request, user)
            return redirect('/')
        else:
            form.add_error(None, "Authentication failed. Please check your credentials.")
            return self.form_invalid(form)

def download_document(request, document_id):
    try:
        # Fetch the document
        document = Document.objects.get(pk=document_id)
        file_path = document.file.path
        signed_document = document.signed_document

        # Verify the server's signature
        if not verify_document_signature(file_path, signed_document):
            raise ValueError("The document's signature could not be verified.")

        # Verify the server certificate using the CA's public key
        if not verify_server_certificate():
            raise ValueError("The server's certificate could not be verified.")

        # Serve the document for download
        with open(file_path, 'rb') as doc_file:
            response = HttpResponse(doc_file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={document.file.name}'
            return response

    except Document.DoesNotExist:
        raise Http404("Document not found.")
    except Exception as e:
        print(f"Error during document download: {e}")
        raise Http404("An error occurred during document download.")

def verify_document_signature(file_path, signature):
    """
    Verify the document's digital signature using the server's public key.
    """
    try:
        with open(settings.SERVER_SIGNING_PUBLIC_KEY_PATH, 'rb') as key_file:
            public_key = load_pem_public_key(key_file.read())

        with open(file_path, 'rb') as doc_file:
            document_content = doc_file.read()

        public_key.verify(
            signature,
            document_content,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Document signature verified successfully.")
        return True
    except Exception as e:
        print(f"Document signature verification failed: {e}")
        return False

def verify_server_certificate():
    """
    Verify the server's certificate using the CA's public key.
    """
    try:
        with open(settings.CA_PUBLIC_KEY_PATH, 'rb') as key_file:
            ca_public_key = load_pem_public_key(key_file.read())

        with open(settings.SERVER_CERT_PATH, 'rb') as cert_file:
            server_cert = x509.load_pem_x509_certificate(cert_file.read())

        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Server certificate verified successfully.")
        return True
    except Exception as e:
        print(f"Server certificate verification failed: {e}")
        return False

# Login
class LoginView(LoginView):
    template_name = 'login.html'
    authentication_form = CustomAuthenticationForm

    def get_success_url(self):
        return '/'
    
# Logout
@csrf_exempt
def logout_view(request):
    logout(request)
    return redirect('/login')




def decrypt_file(encrypted_file_path, encrypted_symmetric_key, private_key_path):
    # Load the private RSA key
    with open(private_key_path, 'rb') as pk_file:
        private_key = serialization.load_pem_private_key(
            pk_file.read(),
            password=None  # Add password if the private key is encrypted
        )

    # Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Read the encrypted file
    with open(encrypted_file_path, 'rb') as ef:
        file_data = ef.read()

    iv = file_data[:16]  # Extract IV
    encrypted_data = file_data[16:]  # Extract encrypted content

    # Decrypt the file content
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path.replace('.enc', '')  # Remove the ".enc" extension


    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
        
    #print(decrypted_file_path[5:])
    return decrypted_file_path
    #return decrypted_data


# Document Download
class DocumentDownloadView(LoginRequiredMixin, View):

    def generate_key_pair(self, private_key_path, public_key_path):
        # Generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Save the private key to a file
        with open(private_key_path, 'wb') as pk_file:
            pk_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),  # Add a password if required
                )
            )

        # Save the public key to a file
        public_key = private_key.public_key()
        with open(public_key_path, 'wb') as pub_file:
            pub_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        return private_key, public_key
    
    def encrypt_file(self, file_object):
        # Generate symmetric key and IV
        symmetric_key = os.urandom(32)  # AES-256 key
        iv = os.urandom(16)  # Initialization Vector (IV)

        # Encrypt file content
        file_data = file_object.read()  # Read file data

        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        encrypted_file_path = f"media/{file_object.name}.enc"
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(iv + encrypted_data)  # Save IV with encrypted data

        # Generate RSA keys
        server_private_key, server_public_key = self.generate_key_pair('server_private_key.pem', 'server_public_key.pem')
        client_private_key, client_public_key = self.generate_key_pair('client_private_key.pem', 'client_public_key.pem')

        # Encrypt symmetric key using the generated RSA public key
        encrypted_symmetric_key = client_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_file_path, encrypted_symmetric_key

    def get(self, request, *args, **kwargs):
        # Get the document object
        document_id = kwargs.get('pk')
        document = get_object_or_404(Document, pk=document_id)

        # Verify file integrity
        file_path = document.file.path  # Assuming `file` is the FileField in the Document model
        if not verify_file_integrity(file_path, document.file_hash):
            return Http404("File integrity check failed. The file may be corrupted.")
        
        # encrypted_file_path, encrypted_symmetric_key = self.encrypt_file(
        #     document.file
        # )

        # Decrypt the encrypted file and get the decrypted file path
#       decrypted_file_path = decrypt_file(encrypted_file_path, encrypted_symmetric_key, 'client_private_key.pem')

#        os.remove(encrypted_file_path)

        # Return the file response if integrity is verified
        response = FileResponse(open(file_path, 'rb'))
        response['Content-Disposition'] = f'attachment; filename="{document.file.name}"'
        return response

def generate_file_hash(file_path):
    """
    Generate a SHA-256 hash for a file.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):  # Read the file in chunks
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def verify_file_integrity(file_path, stored_hash):
    """
    Verify the integrity of a file by comparing its hash with the stored hash.
    """
    current_hash = generate_file_hash(file_path)
    return current_hash == stored_hash

