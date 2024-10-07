from django.urls import path, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from users import views  # Assuming this is where your API views are
from users.views import HomeAPI

# Swagger schema setup (already in your code)
schema_view = get_schema_view(
    openapi.Info(
        title="Your API",
        default_version='v1',
        description="API documentation",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@yourdomain.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # Other API Endpoints
    path('api/register/', views.RegisterAPI.as_view(), name='register'),
    path('api/verify-otp/', views.VerifyOTPAPI.as_view(), name='verify_otp'),
    path('api/set-username/', views.SetUsernameAPI.as_view(), name='set_username'),
    path('api/set-personal-details/', views.SetPersonalDetailsAPI.as_view(), name='set_personal_details'),
    path('api/login/', views.LoginAPI.as_view(), name='login'),
    path('api/logout/', views.LogoutAPI.as_view(), name='logout'),

    # Password Reset
    path('api/request-reset-password/', views.RequestResetPasswordAPI.as_view(), name='request_reset_password'),
    path('api/verify-reset-otp/', views.VerifyResetOTPAPI.as_view(), name='verify_reset_otp'),
    path('api/set-new-password/', views.SetNewPasswordAPI.as_view(), name='set_new_password'),

    # Resend OTP
    path('api/resend-otp/', views.ResendOTPAPI.as_view(), name='resend_otp'),

    # New API Endpoint for setting sport interests
    path('api/set-sport-experience/', views.SetSportExperienceAPI.as_view(), name='set-sport-experience'),

    #Home
    path('api/home/', HomeAPI.as_view(), name='home-api'),

    # friend-request
    path('api/friend-request/',views.SendFriendRequestAPI.as_view(), name='send-friend-request'),
    # update status
    path('api/update-friend-request-status/',views.UpdateFriendRequestStatusAPI.as_view(), name='update_friend_request_status'),
    #handle request 
    path('api/handle-friend-request/', views.HandleFriendRequestAPI.as_view(), name='handle_friend_request'),


    # Swagger and Redoc UI
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

