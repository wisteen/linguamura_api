from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    # Fields to display in the admin list view
    list_display = ('email', 'full_name', 'phone_number', 'country', 'date_of_birth', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff', 'country')  # Filters for the sidebar
    search_fields = ('email', 'full_name', 'phone_number')  # Searchable fields

    # Define the form structure for the detail view
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('full_name', 'phone_number', 'date_of_birth', 'country')}),
        ('Face Authentication', {'fields': ('face_encoding',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    
    # Make `date_joined` read-only
    readonly_fields = ('date_joined',)

    # Fields displayed when adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'full_name', 'password1', 'password2', 'phone_number', 'date_of_birth', 'country'),
        }),
    )

    ordering = ('email',)  # Default ordering
    filter_horizontal = ('groups', 'user_permissions')  # Required for custom permissions

# Register the model and the custom admin
admin.site.register(User, UserAdmin)
