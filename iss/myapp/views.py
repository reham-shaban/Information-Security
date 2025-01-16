from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import LoginView
from django.contrib.auth.mixins import LoginRequiredMixin
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

    def form_valid(self, form):
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
            with open(settings.SERVER_KEY_PATH, 'rb') as key_file:
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

