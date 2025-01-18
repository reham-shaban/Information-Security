import hashlib
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

from myapp.validators import validate_file_extension, virus_scan, validate_file_size, check_suspicious_filename

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
    file = models.FileField(upload_to='documents/', validators=[validate_file_extension, virus_scan, validate_file_size, check_suspicious_filename])
    uploaded_at = models.DateTimeField(auto_now_add=True)

    file_hash = models.CharField(max_length=64, blank=True, null=True)

    #encrypted_key = models.BinaryField(null=True)  # Store the encrypted symmetric key

    def save(self, *args, **kwargs):
        # Prevent updating  after creation
        if self.pk is not None:  # Check if the object already exists (i.e., is being updated)
            raise ValueError("This record cannot be edited after creation.")

        # Save the instance first to ensure `self.file.path` is available
        super().save(*args, **kwargs)

        # Generate and save the file hash if it doesn't exist
        if self.file and not self.file_hash:
            self.file_hash = self.generate_file_hash(self.file.path)
            # Save the hash back to the database
            super().save(update_fields=['file_hash'])

    @staticmethod
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

    def __str__(self):
        return self.name
