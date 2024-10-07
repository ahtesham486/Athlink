from django import forms
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verified = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user.email} - Verified: {self.verified}'


class UserRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")


class OTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'OTP for {self.user.email}'

    def is_expired(self):
        # You can define an expiration logic here, e.g., 10 minutes expiration
        return (timezone.now() - self.created_at).seconds > 60



class JWTToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"JWTToken(user={self.user.username}, token={self.token})"
    


class PersonalDetail(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    address = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)
    language = models.CharField(max_length=50)
    date_of_birth = models.DateField()
    postal_code = models.CharField(max_length=10)
    gender = models.CharField(max_length=10)
    location = models.CharField(max_length=255)
    city =  models.CharField(max_length=255)
    country = models.CharField(max_length=250)
    bio = models.TextField(max_length=250)

    def __str__(self):
        return f"{self.user.email} - Personal Details"



User = get_user_model()

class SportExperience(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    sport = models.CharField(max_length=100)
    experience = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.sport} - {self.experience}"
    

class FriendRequest(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
    )
    
    sender = models.ForeignKey(User, related_name='sent_requests', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_requests', on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('sender', 'receiver')  # Ensure that a user can send only one request to another user at a time

    def __str__(self):
        return f"Request from {self.sender} to {self.receiver} - {self.status}"
    




