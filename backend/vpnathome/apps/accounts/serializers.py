from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


### Validatas the supplied data contains a valid password and email
class LoginSerializer(serializers.Serializer):

    email = serializers.EmailField()
    password = serializers.CharField(max_length=128)

### Validatas the supplied data contains a valid password and email
class RegistrationSerializer(serializers.Serializer):

    email = serializers.EmailField()
    password = serializers.CharField(max_length=128)

    ### Validates that the email is unique
    def validate_email(self, value):
        lowercase_email = value.lower()
        is_unique = User.objects.filter(email=lowercase_email).count() == 0
        if not is_unique:
            raise serializers.ValidationError('E-mail is not available')
        return lowercase_email

    ### Creates a new user with the validated data
    def create(self, validated_data):
        user = User.objects.create(email=validated_data['email'], username=validated_data['email'])
        ### set_password (django.contrib.auth) hashes the plaintext password (no info about hasing available)
        user.set_password(validated_data['password'])
        user.save()
        return user


class UserSerializer(serializers.ModelSerializer):

    ### If no methodname is specified, will default to get_<name>
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'is_superuser', 'permissions']

    ### TODO: We dont yet understand what line 47 does and why superuser is appended at line 49
    def get_permissions(self, instance):
        permissions = list(instance.user_permissions.values_list('codename', flat=True))
        if self.instance.is_superuser:
            permissions.append('superuser')
        return permissions
