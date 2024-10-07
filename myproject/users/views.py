import random
import jwt
import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from .models import JWTToken, PersonalDetail
from .serializers import UserSerializer, PersonalDetailSerializer
from django.contrib.auth import get_user_model, login, authenticate, logout
from .models import SportExperience
from .serializers import SportExperienceSerializer
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.backends import ModelBackend
from .models import FriendRequest, User ,OTP , Profile

User = get_user_model()

def generate_otp():
    return random.randint(100000, 999999)

def send_otp(email, otp):
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp}',
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )


# class RegisterAPI(APIView):
#     def post(self, request):
#         user_data = request.data
#         otp = generate_otp()

#         # Extract the full name and split into first and last names
#         full_name = user_data.get('full_name')
#         if full_name:
#             names = full_name.split(' ', 1)
#             first_name = names[0]
#             last_name = names[1] if len(names) > 1 else ''
#         else:
#             return Response({"error": "Full name is required"}, status=status.HTTP_400_BAD_REQUEST)

#         # Save user data and OTP temporarily
#         request.session['user_data'] = {
#             'first_name': first_name,
#             'last_name': last_name,
#             'email': user_data['email'],
#             'password': user_data['password'],
#             'confirm_password': user_data['confirm_password']
#         }
#         request.session['otp'] = otp

#         send_otp(user_data['email'], otp)
#         return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)

    
# class VerifyOTPAPI(APIView):
#     def post(self, request):
#         otp = request.data.get('otp')
#         session_otp = request.session.get('otp')
#         user_data = request.session.get('user_data')
#         print(request.session.__dict__)
#         if str(session_otp) == otp:
#             user = User(
#                 first_name=user_data['first_name'],
#                 last_name=user_data['last_name'],
#                 email=user_data['email'],
#                 username=user_data['email']  # Temporary username
#             )
#             user.set_password(user_data['password'])
#             user.save()
#             login(request, user, backend='django.contrib.auth.backends.ModelBackend')

#             jwt_payload = {
#                 'user_id': user.id,
#                 'email': user.email,
#             }
#             jwt_token = jwt.encode(jwt_payload, settings.SECRET_KEY, algorithm='HS256')

#             JWTToken.objects.create(user=user, token=jwt_token)

#             # Store the token in the session
#             request.session['jwt_token'] = jwt_token
#             # Clean up session data
#             del request.session['user_data']
#             del request.session['otp']

#             return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)
#         return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)


class RegisterAPI(APIView):
    def post(self, request):
        user_data = request.data
        otp = generate_otp()

        # Extract the full name and split into first and last names
        full_name = user_data.get('full_name')
        if full_name:
            names = full_name.split(' ', 1)
            first_name = names[0]
            last_name = names[1] if len(names) > 1 else ''
        else:
            return Response({"error": "Full name is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the user with `verified=False`
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=user_data['email'],
            username=user_data['email']  # Temporary username
        )
        user.set_password(user_data['password'])
        user.save()

        # Create a profile with `verified=False`
        Profile.objects.create(user=user, verified=False)

        # Save the OTP in the OTP model
        OTP.objects.create(user=user, code=otp)

        # Send OTP
        send_otp(user_data['email'], otp)

        return Response({
            "message": "OTP sent to email successfully",
            "data": {
                "email": user.email,
                "name" :user.first_name + last_name,
                "otp": otp
            }
        }, status=status.HTTP_200_OK)



class VerifyOTPAPI(APIView):
    def post(self, request):
        # Only get the OTP from the request
        otp = request.data.get('otp')

        # Check if OTP is in the request
        if not otp:
            print(f"OTP missing. OTP: {otp}")
            return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Print the incoming OTP for debugging
        print(f"Received OTP: {otp}")

        try:
            # Find the OTP record (assuming OTP is unique per user)
            otp_record = OTP.objects.get(code=otp)

            # Retrieve the user associated with this OTP
            user = otp_record.user

            # Print the stored OTP for comparison
            print(f"Stored OTP: {otp_record.code} for user: {user.email}")

            # If the OTP matches, proceed with verification
            if str(otp_record.code) == str(otp):
                # Mark the user as verified
                profile = Profile.objects.get(user=user)
                profile.verified = True
                profile.save()

                # Print verification success
                print(f"User {user.email} verified successfully")

                # Generate JWT token
                jwt_payload = {
                    'user_id': user.id,
                    'email': user.email,
                }
                jwt_token = jwt.encode(jwt_payload, settings.SECRET_KEY, algorithm='HS256')

                # Print JWT token generation
                print(f"JWT Token generated: {jwt_token}")

                # Store the token in JWTToken model (optional)
                JWTToken.objects.create(user=user, token=jwt_token)

                # Return the JWT token in response
                return Response({
                    "message": "OTP verified successfully",
                    "token": jwt_token,
                    "data": {
                        "email": user.email,
                        "otp": otp_record.code
                    }
                }, status=status.HTTP_200_OK)
            else:
                # Print invalid OTP message
                print(f"Invalid OTP: {otp}")
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        except OTP.DoesNotExist:
            # Print OTP not found error
            print(f"OTP not found for: {otp}")
            return Response({"error": "OTP not found"}, status=status.HTTP_404_NOT_FOUND)
        except Profile.DoesNotExist:
            # Handle if somehow the user doesn't have a profile yet
            print(f"Profile not found for user: {user.email}")
            return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)





class SetUsernameAPI(APIView):
    def post(self, request):
        # Get the JWT token from the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            print("Authorization header missing or malformed")
            return Response({"error": "Authorization token is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Extract the token from the header
        jwt_token = auth_header.split(' ')[1]
        print(f"JWT Token extracted: {jwt_token}")

        try:
            # Decode the JWT token to get the user's information
            payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            print(f"User found: {user.email} (ID: {user.id})")
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            print("Invalid or expired token")
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            print(f"User not found for ID: {payload['user_id']}")
            return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

        # Get the username from the request data
        username = request.data.get('username')
        if not username:
            print("Username missing in request data")
            return Response({"error": "Username is required"}, status=status.HTTP_400_BAD_REQUEST)

        print(f"Requested username: {username}")

        # Check if the username is already taken
        if User.objects.filter(username=username).exists():
            print(f"Username '{username}' is already taken")
            return Response({"error": "Username already taken"}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new username for the user
        user.username = username
        user.save()

        print(f"Username for user {user.email} set to: {username}")

        return Response({
            "message": "Username set successfully",
            "token": jwt_token,
            "data": {
                "email": user.email,
                "username": user.username
            }
        }, status=status.HTTP_200_OK)



    

class SetPersonalDetailsAPI(APIView):
    def post(self, request):
        # Try to get the JWT token from the session first
        jwt_token = request.session.get('jwt_token')
        if not jwt_token:
            # If not found in session, try to get it from the Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    token_type, jwt_token = auth_header.split(' ')
                    if token_type.lower() != 'bearer':
                        return Response({"error": "Invalid token type. Bearer token expected."}, status=status.HTTP_400_BAD_REQUEST)
                except ValueError:
                    return Response({"error": "Invalid Authorization header format"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "Authorization token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode the JWT token to retrieve the user information
            payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

        # Handle personal details
        serializer = PersonalDetailSerializer(data=request.data)
        if serializer.is_valid():
            # Update or create the personal details for the authenticated user
            PersonalDetail.objects.update_or_create(
                user=user,
                defaults=serializer.validated_data
            )
            return Response({"message": "Personal details set successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)







class LoginAPI(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        # Print debug information
        print(f"Email: {email}")
        print(f"Password: {password}")

        user = authenticate(request, email=email, password=password)
        
        if user:
            # Optionally, login the user here if you want to maintain a session
            login(request, user)
            return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPI(APIView):
    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)

class ResendOTPAPI(APIView):
    def post(self, request):
        # Retrieve the email from the session
        user_data = request.session.get('user_data')
        if not user_data or 'email' not in user_data:
            return Response({"error": "No email found. Please start the registration process again."}, status=status.HTTP_400_BAD_REQUEST)

        email = user_data['email']

        # Generate a new OTP
        otp = generate_otp()

        # Update the OTP in the session
        request.session['otp'] = otp

        # Resend the OTP to the user's email
        send_otp(email, otp)
        return Response({"message": "OTP has been resent to your email"}, status=status.HTTP_200_OK)


class RequestResetPasswordAPI(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        otp = generate_otp()

        # Save OTP in the session
        request.session['reset_otp'] = otp
        request.session['reset_email'] = email

        send_otp(email, otp)
        return Response({"message": "OTP has been sent to your email"}, status=status.HTTP_200_OK)
    
class VerifyResetOTPAPI(APIView):
    def post(self, request):
        otp = request.data.get('otp')
        session_otp = request.session.get('reset_otp')
        email = request.session.get('reset_email')

        if not otp or not session_otp:
            return Response({"error": "OTP is required"}, status=status.HTTP_400_BAD_REQUEST)

        if str(session_otp) == otp:
            # OTP is correct
            # Clean up session data for security
            del request.session['reset_otp']

            return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)
        
        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)




class SetNewPasswordAPI(APIView):
    def post(self, request):
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        email = request.session.get('reset_email')

        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not password or not confirm_password:
            return Response({"error": "Password and Confirm Password are required"}, status=status.HTTP_400_BAD_REQUEST)

        if password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()
        del request.session['reset_email']
        return Response({"message": "Password has been reset successfully"}, status=status.HTTP_200_OK)
    



class SetSportExperienceAPI(APIView):
    def post(self, request):
        # Try to get the JWT token from the session first
        jwt_token = request.session.get('jwt_token')

        if not jwt_token:
            # If not found in session, try to get it from the Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header:
                try:
                    token_type, jwt_token = auth_header.split(' ')
                    if token_type.lower() != 'bearer':
                        return Response({"error": "Invalid token type. Bearer token expected."}, status=status.HTTP_400_BAD_REQUEST)
                except ValueError:
                    return Response({"error": "Invalid Authorization header format"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "Authorization token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode the JWT token to retrieve the user information
            payload = jwt.decode(jwt_token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

        # Process the incoming data
        sport_experience_data = request.data
        
        if not isinstance(sport_experience_data, list):
            return Response({"error": "Data should be a list of sport-experience objects"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = SportExperienceSerializer(data=sport_experience_data, many=True)
        if serializer.is_valid():
            # Save or update the sport experiences
            for item in serializer.validated_data:
                SportExperience.objects.update_or_create(
                    user=user,
                    sport=item['sport'],
                    defaults={'experience': item['experience']}
                )
            return Response({"message": "Sport experiences updated successfully"}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class HomeAPI(APIView):
    def get(self, request):
        # Ensure the user is authenticated
        if not request.user.is_authenticated:
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)

        logged_in_user = request.user  # Get the logged-in user

        # Fetch the logged-in user's sport experiences
        logged_in_sport_experiences = SportExperience.objects.filter(user=logged_in_user)
        logged_in_sports = {exp['sport'] for exp in SportExperienceSerializer(logged_in_sport_experiences, many=True).data}

        # Fetch the logged-in user's personal details
        logged_in_personal_detail = PersonalDetail.objects.filter(user=logged_in_user).first()
        logged_in_city = logged_in_personal_detail.city if logged_in_personal_detail else ""
        logged_in_language = logged_in_personal_detail.language if logged_in_personal_detail else ""

        print(f"Logged-in user's sports: {logged_in_sports}")  # Debug print
        print(f"Logged-in user's city: {logged_in_city}")  # Debug print
        print(f"Logged-in user's language: {logged_in_language}")  # Debug print

        # Fetch all users excluding the logged-in user
        users = User.objects.exclude(id=logged_in_user.id)
        filtered_users = []

        for user in users:
            # Fetch sport experiences and personal details for each user
            sport_experiences = SportExperience.objects.filter(user=user)
            sport_experiences_data = SportExperienceSerializer(sport_experiences, many=True).data

            personal_detail = PersonalDetail.objects.filter(user=user).first()
            user_city = personal_detail.city if personal_detail else ""
            user_language = personal_detail.language if personal_detail else ""

            # Get sports for the current user
            user_sports = {exp['sport'] for exp in sport_experiences_data}

            # Check for any intersection between logged-in user's sports and current user's sports
            matched_sports = logged_in_sports.intersection(user_sports)
            city_match = logged_in_city == user_city
            language_match = logged_in_language == user_language

            # Check if the logged-in user has sent a friend request to this user (receiver)
            is_like = FriendRequest.objects.filter(sender=logged_in_user, receiver=user).exists()

            # If matched sports, city, or language exists, add user info to filtered_users
            if matched_sports or city_match or language_match:
                print(f"Matched sports for user {user.username}: {matched_sports}")  # Debug print
                print(f"City match for user {user.username}: {city_match}")  # Debug print
                print(f"Language match for user {user.username}: {language_match}")  # Debug print

                user_info = {
                    "username": user.username,
                    "email": user.email,
                    "personal_detail": {
                        "address": personal_detail.address if personal_detail else "",
                        "phone_number": personal_detail.phone_number if personal_detail else "",
                        "language": user_language,
                        "date_of_birth": personal_detail.date_of_birth if personal_detail else "",
                        "postal_code": personal_detail.postal_code if personal_detail else "",
                        "gender": personal_detail.gender if personal_detail else "",
                        "location": personal_detail.location if personal_detail else "",
                        "city": user_city,
                        "country": personal_detail.country if personal_detail else "",
                        "bio": personal_detail.bio if personal_detail else ""
                    },
                    "sport_experience": sport_experiences_data,
                    "is_like": is_like  # Add the is_like flag
                }

                filtered_users.append(user_info)

        return Response({"users": filtered_users}, status=status.HTTP_200_OK)




class SendFriendRequestAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        receiver_id = request.data.get('receiver_id')
        if not receiver_id:
            return Response({"error": "Receiver ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            receiver = User.objects.get(id=receiver_id)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"}, status=status.HTTP_404_NOT_FOUND)

        if request.user == receiver:
            return Response({"error": "You cannot send a request to yourself"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a reciprocal request exists
        reciprocal_request_exists = FriendRequest.objects.filter(
            sender=receiver, receiver=request.user
        ).exists()

        if reciprocal_request_exists:
            return Response({"error": "A reciprocal request exists. You cannot send a request back to the receiver."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a request already exists between these two users
        if FriendRequest.objects.filter(sender=request.user, receiver=receiver).exists():
            return Response({"error": "Request already sent"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the friend request
        friend_request = FriendRequest(sender=request.user, receiver=receiver)
        friend_request.save()

        return Response({"message": "Friend request sent successfully"}, status=status.HTTP_201_CREATED)

    def get(self, request, *args, **kwargs):
        # Get all friend requests related to the user as either sender or receiver
        friend_requests = FriendRequest.objects.filter(
            sender=request.user
        ) | FriendRequest.objects.filter(receiver=request.user)

        # Fetch detailed information for each friend request
        requests_data = []
        for friend_request in friend_requests:
            sender_data = UserSerializer(friend_request.sender).data
            receiver_data = UserSerializer(friend_request.receiver).data

            request_data = {
                "id": friend_request.id,
                "sender": sender_data,
                "receiver": receiver_data,
                "status": friend_request.status,
                "created_at": friend_request.created_at
            }
            requests_data.append(request_data)

        return Response({"friend_requests": requests_data}, status=status.HTTP_200_OK)

class UpdateFriendRequestStatusAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request_id = request.data.get('request_id')
        new_status = request.data.get('status')

        if not request_id or not new_status:
            return Response({"error": "Request ID and status are required"}, status=status.HTTP_400_BAD_REQUEST)

        valid_statuses = ['pending', 'accepted', 'rejected']
        if new_status not in valid_statuses:
            return Response({"error": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the friend request by ID
            friend_request = FriendRequest.objects.get(id=request_id)
        except FriendRequest.DoesNotExist:
            return Response({"error": "Friend request not found"}, status=status.HTTP_404_NOT_FOUND)

        if friend_request.receiver != request.user and friend_request.sender != request.user:
            return Response({"error": "You are not authorized to update this request"}, status=status.HTTP_403_FORBIDDEN)

        # Update the status
        friend_request.status = new_status
        friend_request.save()

        return Response({"message": "Friend request status updated successfully"}, status=status.HTTP_200_OK)

class HandleFriendRequestAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        receiver_id = request.data.get('receiver_id')
        
        if not receiver_id:
            return Response({"error": "Receiver ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            receiver = User.objects.get(id=receiver_id)
        except User.DoesNotExist:
            return Response({"error": "Receiver not found"}, status=status.HTTP_404_NOT_FOUND)

        if request.user == receiver:
            return Response({"error": "You cannot send a request to yourself"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if a request already exists from receiver to sender
        existing_request = FriendRequest.objects.filter(sender=receiver, receiver=request.user).first()

        if existing_request:
            # If an existing request is found, update the status to 'accepted'
            existing_request.status = 'accepted'
            existing_request.save()
            return Response({"message": "Friend request status updated to accepted"}, status=status.HTTP_200_OK)

        # Check if a request is already sent from sender to receiver
        if FriendRequest.objects.filter(sender=request.user, receiver=receiver).exists():
            return Response({"error": "Request already sent"}, status=status.HTTP_400_BAD_REQUEST)

        # Create the new friend request
        friend_request = FriendRequest(sender=request.user, receiver=receiver)
        friend_request.save()

        return Response({"message": "Friend request sent successfully"}, status=status.HTTP_201_CREATED)
        
    def get(self, request, *args, **kwargs):
        # Get all friend requests related to the user as either sender or receiver
        friend_requests = FriendRequest.objects.filter(
            sender=request.user
        ) | FriendRequest.objects.filter(receiver=request.user)

        # Fetch detailed information for each friend request
        requests_data = []
        for friend_request in friend_requests:
            sender_data = UserSerializer(friend_request.sender).data
            receiver_data = UserSerializer(friend_request.receiver).data

            request_data = {
                "id": friend_request.id,
                "sender": sender_data,
                "receiver": receiver_data,
                "status": friend_request.status,
                "created_at": friend_request.created_at
            }
            requests_data.append(request_data)

        return Response({"friend_requests": requests_data}, status=status.HTTP_200_OK)

