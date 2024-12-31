from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import LoginView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView, TemplateView
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse_lazy

from .forms import CustomUserCreationForm, CustomAuthenticationForm, DocumentUploadForm
from .models import CustomUser, Document

# Create your views here.
# Home View
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views.generic import TemplateView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import Document, CustomUser
from .forms import DocumentUploadForm, DocumentSearchForm


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

# Document Upload View
class DocumentUploadView(LoginRequiredMixin, CreateView):
    model = Document
    form_class = DocumentUploadForm
    template_name = 'upload_document.html'
    success_url = reverse_lazy('home')  # Redirect to the home page after upload

    def form_valid(self, form):
        form.instance.user = self.request.user  # Associate the document with the logged-in user
        return super().form_valid(form)


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

