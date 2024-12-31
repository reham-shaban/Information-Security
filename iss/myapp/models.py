from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

# User Model
class CustomUserManager(BaseUserManager):
    def create_user(self, national_number, password=None, **extra_fields):
        if not national_number:
            raise ValueError("The National Number is required.")
        extra_fields.setdefault('role', 'user')  # Default role is 'user'
        user = self.model(national_number=national_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, national_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(national_number, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('user', 'User'),
        ('employee', 'Employee'),
    ]

    name = models.CharField(max_length=255)
    national_number = models.CharField(max_length=14, unique=True)
    birthday = models.DateField()
    phone_number = models.CharField(max_length=15)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'national_number'
    REQUIRED_FIELDS = ['name', 'birthday', 'phone_number']

    def __str__(self):
        return f"{self.name} ({self.role})"

# Document Model
class Document(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='documents')
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
