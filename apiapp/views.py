from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class RegisterView(APIView):
    def post(self, request):
        # Registration logic (assuming success)
        response_data = {
            "status": 201,
            "data": {"message": "User registered successfully"},
            "message": "User registered successfully"
        }
        return Response(response_data, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        email = request.data.get("email", None)
        
        # Check if username exists
        if not User.objects.filter(username=username).exists():
            return Response({
                "status": 404,
                "data": [],
                "message": "Username does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Authenticate user
        user = authenticate(username=username, password=password)
        
        # Check if password is correct
        if user is None:
            return Response({
                "status": 406,
                "data": [],
                "message": "Incorrect password. Try again with a different password."
            }, status=status.HTTP_406_NOT_ACCEPTABLE)
        
        # Check if email matches (if provided)
        if email and user.email != email:
            return Response({
                "status": 401,
                "data": [],
                "message": "Email does not match. Try again with the correct email."
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # All checks passed, return tokens
        if email and user.email == email:
            refresh = RefreshToken.for_user(user)
            return Response({
                "status": 201,
                "data": {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh)
                },
                "message": "Login successful"
            }, status=status.HTTP_201_CREATED)
        
        # If username is correct but email or password is incorrect
        if not email:
            return Response({
                "status": 409,
                "data": [],
                "message": "Username or password incorrect."
            }, status=status.HTTP_409_CONFLICT)
        
        return Response({
            "status": 401,
            "data": [],
            "message": "Authentication failed"
        }, status=status.HTTP_401_UNAUTHORIZED)
