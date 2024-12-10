from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator

def send_activation_email(request, user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    activation_link = f"{request.build_absolute_uri('/activate/')}?uid={uid}&token={token}"

    subject = "Activate Your Account"
    message = render_to_string('email/activation_email.html', {
        'user': user,
        'activation_link': activation_link,
    })
    send_mail(subject, message, 'no-reply@example.com', [user.email])
