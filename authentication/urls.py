from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from .views import RegisterView, LoginView, LogoutView, ActivateAccountView

from drf_yasg import openapi
from . import views
from django.contrib.auth import views as form_validation

# Schema View
schema_view = get_schema_view(
    openapi.Info(
        title="Linguamura Authentication API",
        default_version='v1',
        description="API documentation for User Authentication user can register, login, logout and update details",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="hello@linguamura.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Swagger UI
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('register/', RegisterView.as_view(), name='register'),
    path('activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view(), name='activate-account'),

    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # Your other API endpoints
    # path('api/register/', RegisterAPI.as_view(), name='register'),
    # path('api/activate/', activate_account, name='activate'),
]
