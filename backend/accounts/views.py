from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.models import User, Group
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# Create your views here.

class LoginView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(csrf_exempt)
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, username=email, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            # Determine user role
            if user.is_superuser or user.groups.filter(name='admin').exists():
                role = 'admin'
            elif user.is_staff or user.groups.filter(name='staff').exists():
                role = 'staff'
            elif user.groups.filter(name='teacher').exists():
                role = 'teacher'
            else:
                role = 'student'

            response = Response({
                'message': 'Login successful',
                'access': access_token,
                'refresh': refresh_token,
                'role': role
            }, status=status.HTTP_200_OK)
            response.set_cookie('access', access_token, httponly=True, secure=False, samesite='Lax', domain='.localhost')
            response.set_cookie('refresh', refresh_token, httponly=True, secure=False, samesite='Lax', domain='.localhost')
            return response
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    def post(self, request):
        response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        response.delete_cookie('access')
        response.delete_cookie('refresh')
        return response

class TokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh')
        if not refresh_token:
            return Response({'error': 'No refresh token provided'}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            response = Response({'message': 'Token refreshed'}, status=status.HTTP_200_OK)
            response.set_cookie('access', access_token, httponly=True, secure=False, samesite='Lax', domain='.localhost')
            return response
        except TokenError:
            return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role', 'viewer')  # default role

        if not email or not password:
            return Response({'error': 'Email and password required'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=email).exists():
            return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=email, email=email, password=password)

        # Assign user to group (role)
        group, created = Group.objects.get_or_create(name=role)
        user.groups.add(group)
        return Response({'message': f'Registration successful. Assigned role: {role}'}, status=status.HTTP_201_CREATED)

class AdminOnlyView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.groups.filter(name='admin').exists():
            return Response({'error': 'You are not an admin'}, status=status.HTTP_403_FORBIDDEN)
        return Response({'message': 'Welcome, admin!'}, status=status.HTTP_200_OK)

def jwt_response_payload_handler(token, user=None, request=None):
    # Determine user role (customize as needed)
    if hasattr(user, 'role'):
        role = user.role
    elif user.is_superuser or user.groups.filter(name='admin').exists():
        role = 'admin'
    elif user.is_staff or user.groups.filter(name='staff').exists():
        role = 'staff'
    elif user.groups.filter(name='teacher').exists():
        role = 'teacher'
    else:
        role = 'student'
    return {
        'token': token,
        'role': role,
    }
