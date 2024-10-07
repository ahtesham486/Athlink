from django import forms
from django.contrib.auth import get_user_model,authenticate


from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class UserRegistrationForm(forms.ModelForm):
    full_name = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = User
        fields = ['full_name', 'email', 'password']
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        if password != confirm_password:
            raise forms.ValidationError("Passwords do not match.")
        email = cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return cleaned_data

    
class UsernameForm(forms.Form):
    username = forms.CharField(max_length=150, required=True, label='Username')
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already taken.")
        return username
    

class UserLoginForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = forms.CharField(widget=forms.PasswordInput, label='Password')

    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        if email and password:
            self.user = authenticate(username=email, password=password)
            if not self.user:
                raise forms.ValidationError("Invalid email or password.")
        return self.cleaned_data

    def get_user(self):
        return self.user
    

from .models import PersonalDetail

class PersonalDetailForm(forms.ModelForm):
    class Meta:
        model = PersonalDetail
        fields = ['phone_number', 'language', 'joining_date', 'gender', 'postal_code', 'location' ,'city', 'country' , 'bio']
        widgets = {
            'joining_date': forms.DateInput(attrs={'type': 'date'}),
        }
