from django.contrib import admin
from .models import CustomUser, Document

# CustomeUser Admin
@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ['name', 'national_number', 'role', 'is_active', 'is_staff']
    list_filter = ['role', 'is_active', 'is_staff']
    search_fields = ['name', 'national_number']
    fields = ['name', 'national_number', 'birthday', 'phone_number', 'role', 'is_active', 'is_staff', 'is_superuser', 'password']
    readonly_fields = ['password']

# Document Admin
@admin.register(Document)
class DocumentAdmin(admin.ModelAdmin):
    list_display = ['name', 'user', 'file', 'uploaded_at']
    search_fields = ['name', 'user__name']
    list_filter = ['user']