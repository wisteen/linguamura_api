from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from .models import User
from .serializers import RegistrationSerializer
import uuid



from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from django.template.loader import render_to_string
from sendgrid.helpers.mail import *
import os
import sendgrid

from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_str
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator


class RegisterView(APIView):
    """
    API endpoint for user registration.
    """
    @swagger_auto_schema(
        operation_description="Register a new user and send email verification link",
        request_body=RegistrationSerializer,
        responses={
            status.HTTP_201_CREATED: "Registration successful. Please check your email to verify your account.",
            status.HTTP_400_BAD_REQUEST: "Bad request or validation error."
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            # Save the user with `is_active=False`
            user = serializer.save(is_active=False)
            email = user.email
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            verification_url = f"{request.build_absolute_uri('/auth/activate/')}{uidb64}/{token}/"

            from_email=Email('hello@linguamura.com')
            to_emails=To(email)
            subject='Verify Your Email'
            email_content = render_to_string("email_verification.html", {"verification_url": verification_url, "user": user})
            mail=Mail(from_email,to_emails,subject, Content("text/html", email_content))
            print(email)
            try:
                # Send the email via SendGrid
                sg = sendgrid.SendGridAPIClient(settings.SENDGRID_API_KEY)
                response = sg.client.mail.send.post(request_body=mail.get())
                if response.status_code in [200, 202]:
                    return Response(
                        {"message": "Registration successful. Please check your email to verify your account."},
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    return Response(
                        {"error": "Registration successful but failed to send email. Please contact support."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
            except Exception as e:
                return Response(
                    {"error": f"An error occurred while sending email: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ActivateAccountView(APIView):
    """
    API endpoint to activate a user's account.
    """

    def get(self, request, uidb64, token, *args, **kwargs):
        User = get_user_model()
        try:
            # Decode the user ID from the URL
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid or expired activation link."}, status=status.HTTP_400_BAD_REQUEST)

        # Check the token validity
        if default_token_generator.check_token(user, token):
            if user.is_active:
                return Response({"message": "Account is already verified."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Activate the user
            user.is_active = True
            user.save()

            return Response({"message": "Account activated successfully. You can now log in."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired activation token."}, status=status.HTTP_400_BAD_REQUEST)





from rest_framework.authtoken.models import Token  # For token-based authentication
from django.contrib.auth import authenticate
from .serializers import LoginSerializer, LogoutSerializer


class LoginView(APIView):
    """
    API endpoint for user login.
    """
    @swagger_auto_schema(
        operation_description="Login",
        request_body=LoginSerializer,
        responses={
            status.HTTP_200_OK: "Login successful.",
            status.HTTP_400_BAD_REQUEST: "Invalid email or password.",
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            # Authenticate the user
            user = authenticate(request, email=email, password=password)
            if user:
                if user.is_active:
                    # Generate or get the authentication token
                    token, _ = Token.objects.get_or_create(user=user)
                    return Response({"token": token.key}, status=status.HTTP_200_OK)
                return Response({"error": "Account is inactive. Please verify your email."}, status=status.HTTP_403_FORBIDDEN)
            return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



from rest_framework.permissions import IsAuthenticated

from rest_framework.authentication import TokenAuthentication

class LogoutView(APIView):
    """
    API endpoint for user logout, requiring the token.
    """
    @swagger_auto_schema(
        operation_description="Logout a user by providing their token.",
        request_body=LogoutSerializer,
        responses={
            status.HTTP_200_OK: "Logged out successfully.",
            status.HTTP_400_BAD_REQUEST: "Invalid or missing token.",
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Access the validated token instance
        token_instance = serializer.token_instance

        try:
            # Delete the token to log out the user
            token_instance.delete()
            return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": f"Failed to log out: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
