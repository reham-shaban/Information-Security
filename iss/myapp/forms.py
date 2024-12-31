from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.hashers import make_password
from .models import CustomUser, Document

# User forms
class CustomUserCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ['name', 'national_number', 'birthday', 'phone_number', 'password']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.password = make_password(self.cleaned_data['password'])  # Hash the password
        user.role = 'user'  # Always set the role to 'user' during registration
        if commit:
            user.save()
        return user

class CustomAuthenticationForm(AuthenticationForm):
    username = forms.CharField(label="National Number")
    username.field_name = 'national_number'

# Document forms
class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ['name', 'file']

class DocumentSearchForm(forms.Form):
    national_number = forms.CharField(max_length=14, required=True, label='National Number')
