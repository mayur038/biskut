from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions,generics
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from .utils import send_verification_email
from django.http import HttpResponse
from django.shortcuts import render
User = get_user_model()



# #
# for Sweets
# #
from rest_framework.exceptions import NotFound, PermissionDenied
from . models import Sweet
from . serializer import SweetSerializer
from . permissions import IsAdminUser

# your_app/views.py

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]  # anyone can register

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role', 'user')  # default to 'user' if not given

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        if role == 'admin':
            if not request.user.is_authenticated or request.user.role != 'admin':
                return Response({"error": "Only admins can create admin users."}, status=status.HTTP_403_FORBIDDEN)

        user = User.objects.create_user(username=username, email=email, password=password, role=role,is_staff = True)
        send_verification_email(user)
        return Response(
            {
                "message": f"{role.title()} user created. Please verify your email.",
                "user": {"username": user.username, "email": user.email, "role": user.role}
            },
            status=status.HTTP_201_CREATED
        )
    
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]  # anyone can register
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user is None:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_email_verified:
            return Response({"error": "Please verify your email first."}, status=status.HTTP_403_FORBIDDEN)

        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "username": user.username,
            "role": user.role,
            "verified":user.is_email_verified
        })

class VerifyEmailView(APIView):
    permission_classes = []  # allow anyone

    def get(self, request):
        token = request.query_params.get('token')

        if not token:
            return HttpResponse("<h2>Invalid verification link.</h2>", status=400)

        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
            user.is_email_verified = True
            user.save()
           
            return render(request, 'email_verification/verified.html')
        except Exception as e:
            return HttpResponse("<h2>Invalid or expired token.</h2>", status=400)
        

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Frontend should delete tokens locally
        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
    
#
# Sweet operations
# ##

class SweetListView(generics.ListAPIView):
    queryset = Sweet.objects.all().order_by('name')
    serializer_class = SweetSerializer
    permission_classes = [permissions.IsAuthenticated]

# CREATE sweet (Admin only)
class SweetCreateView(generics.CreateAPIView):
    queryset = Sweet.objects.all()
    serializer_class = SweetSerializer
    permission_classes = [IsAdminUser]
    
# UPDATE sweet (Admin only)
class SweetUpdateView(generics.UpdateAPIView):
    queryset = Sweet.objects.all()
    serializer_class = SweetSerializer
    permission_classes = [IsAdminUser]

    def get_object(self):
        try:
            return Sweet.objects.get(pk=self.kwargs['pk'])
        except Sweet.DoesNotExist:
            raise NotFound("Sweet not found.")

# DELETE sweet (Admin only)
class SweetDeleteView(generics.DestroyAPIView):
    queryset = Sweet.objects.all()
    serializer_class = SweetSerializer
    permission_classes = [IsAdminUser]

    def get_object(self):
        try:
            return Sweet.objects.get(pk=self.kwargs['pk'])
        except Sweet.DoesNotExist:
            raise NotFound("Sweet not found.")