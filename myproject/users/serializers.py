from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import PersonalDetail

User = get_user_model()
from rest_framework import serializers
from .models import SportExperience
from .models import FriendRequest

class FriendRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = FriendRequest
        fields = ['id', 'sender', 'receiver', 'status', 'created_at']
        read_only_fields = ['id', 'status', 'created_at']

class SportExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = SportExperience
        fields = ['sport', 'experience']




class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'username']


class PersonalDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = PersonalDetail
        fields = [
            'address', 'phone_number', 'language', 'date_of_birth',
            'postal_code', 'gender', 'location', 'city' , 'country' , 'bio'
        ]
