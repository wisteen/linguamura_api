from rest_framework import serializers
from .models import User
import uuid

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, default="dummyPassword123")  # Default password
    full_name = serializers.CharField(default="John Doe")  # Default full name
    email = serializers.EmailField(default="john.doe@example.com")  # Default email
    phone_number = serializers.CharField(default="1234567890")  # Default phone number
    date_of_birth = serializers.DateField(default="1990-01-01")  # Default date of birth
    country = serializers.CharField(default="Nigeria")  # Default country
    face_encoding = serializers.CharField(default="dummyFaceEncodingData")  # Default face encoding string

    class Meta:
        model = User
        fields = ['full_name', 'email', 'phone_number', 'date_of_birth', 'country', 'password', 'face_encoding']

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        if password:
            user.set_password(password)
        user.email_verification_token = uuid.uuid4()  # Set email verification token
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(default="example@example.com")
    password = serializers.CharField(write_only=True, default="dummyPassword123")

class LogoutSerializer(serializers.Serializer):
    """
    Serializer for logout, requiring the token to be explicitly provided.
    """
    token = serializers.CharField(required=True)

    def validate(self, data):
        """
        Validate that the provided token is valid.
        """
        from rest_framework.authtoken.models import Token
        token = data.get("token")

        try:
            self.token_instance = Token.objects.get(key=token)
        except Token.DoesNotExist:
            raise serializers.ValidationError("Invalid token.")

        return data
