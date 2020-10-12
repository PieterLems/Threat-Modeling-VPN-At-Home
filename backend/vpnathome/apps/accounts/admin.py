from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as CoreUserAdmin
from django.contrib.auth.forms import UserChangeForm as CoreUserChangeForm, UserCreationForm as CoreUserCreationForm
from django.utils.translation import ugettext_lazy as _

from .models import User



### Form class for updating user data
class UserChangeForm(CoreUserChangeForm):

    class Meta(CoreUserChangeForm.Meta):
        model = User


### Form class for creating a new user
class UserCreationForm(CoreUserCreationForm):

    class Meta:
        from django.forms import EmailField
        model = User
        fields = ("email",)
        field_classes = {'email': EmailField}


### Admin database model
class UserAdmin(CoreUserAdmin):

    ### Assign the form classes to the admin to introduce this funtionality to the user
    form = UserChangeForm
    add_form = UserCreationForm

    fieldsets = (
        (None, {'fields': ('email', 'password', )}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        # Permissions are (currently) not used
        # (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
        #                                'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )

    # add_fieldsets are copied from base class verbatim and modified:
    #   * added firebase authentication
    #   * added section titles

    add_fieldsets = (
        (_('Basic user data'), {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )

    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active', 'is_superuser')

### Register the models
admin.site.register(User, UserAdmin)
