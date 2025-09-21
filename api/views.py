"""
@description: API views for User Authentication and Sweet Shop management
@author: Mayur Gohil
@date_of_modification: 22-Sep-2025
"""

from django.contrib.auth import authenticate, get_user_model
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken, TokenError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, generics
from django.http import HttpResponse
from django.shortcuts import render
from .utils import send_verification_email
from .models import Sweet, InventoryLog
from .serializer import SweetSerializer
from .permissions import IsAdminUser
from rest_framework.exceptions import NotFound, PermissionDenied
from django.utils import timezone

User = get_user_model()


# ---------------------------------------------
# USER AUTHENTICATION APIS
# ---------------------------------------------

class RegisterView(APIView):
    """
    @description: API to register a new user. Admin creation restricted to admin users.
    @input_json: {"username": "", "email": "", "password": "", "role": "user/admin"}
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role', 'user')

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)

        if role == 'admin':
            if not request.user.is_authenticated or request.user.role != 'admin':
                return Response({"error": "Only admins can create admin users."}, status=status.HTTP_403_FORBIDDEN)

        user = User.objects.create_user(username=username, email=email, password=password, role=role, is_staff=True)
        send_verification_email(user)
        return Response(
            {
                "message": f"{role.title()} user created. Please verify your email.",
                "user": {"username": user.username, "email": user.email, "role": user.role}
            },
            status=status.HTTP_201_CREATED
        )


class LoginView(APIView):
    """
    @description: API to authenticate a user and return JWT tokens along with user info.
    @input_json: {"username": "", "password": ""}
    """
    permission_classes = [permissions.AllowAny]

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
            "verified": user.is_email_verified
        })


class VerifyEmailView(APIView):
    """
    @description: API to verify user email via token in query params.
    @input_query: ?token=<access_token>
    """
    permission_classes = []

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
            return render(request, 'EmailVerification.html')
        except Exception:
            return render(request, 'EmailVerification.html')


class LogoutView(APIView):
    """
    @description: API to log out the user. Frontend should clear tokens locally.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)


# ---------------------------------------------
# SWEET MANAGEMENT APIS
# ---------------------------------------------

class SweetListView(generics.ListAPIView):
    """
    @description: Get list of all sweets, ordered by name
    """
    queryset = Sweet.objects.all().order_by('name')
    serializer_class = SweetSerializer
    permission_classes = [permissions.IsAuthenticated]


class SweetCreateView(generics.CreateAPIView):
    """
    @description: Create a new sweet (Admin only)
    @input_json: {"name": "", "category": "", "price": 0.0, "quantity": 0}
    """
    queryset = Sweet.objects.all()
    serializer_class = SweetSerializer
    permission_classes = [IsAdminUser]


class SweetUpdateView(generics.UpdateAPIView):
    """
    @description: Update sweet details (Admin only)
    @input_json: {"name": "", "category": "", "price": 0.0, "quantity": 0}
    """
    queryset = Sweet.objects.all()
    serializer_class = SweetSerializer
    permission_classes = [IsAdminUser]

    def get_object(self):
        try:
            return Sweet.objects.get(pk=self.kwargs['pk'])
        except Sweet.DoesNotExist:
            raise NotFound("Sweet not found.")


class SweetDeleteView(generics.DestroyAPIView):
    """
    @description: Delete a sweet (Admin only)
    """
    queryset = Sweet.objects.all()
    serializer_class = SweetSerializer
    permission_classes = [IsAdminUser]

    def get_object(self):
        try:
            return Sweet.objects.get(pk=self.kwargs['pk'])
        except Sweet.DoesNotExist:
            raise NotFound("Sweet not found.")


class SweetPurchaseView(APIView):
    """
    @description: Purchase a sweet (Customer only). Decreases sweet quantity by 1 and logs inventory.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        try:
            sweet = Sweet.objects.get(pk=pk)
            if sweet.quantity <= 0:
                return Response({"error": "Sweet is out of stock"}, status=status.HTTP_400_BAD_REQUEST)
            sweet.quantity -= 1
            sweet.save()
            InventoryLog.objects.create(
                sweet=sweet,
                action='purchase',
                quantity_changed=1,
                performed_by=request.user,
                timestamp=timezone.now()
            )
            return Response({"message": "Sweet purchased successfully"}, status=status.HTTP_200_OK)
        except Sweet.DoesNotExist:
            return Response({"error": "Sweet not found"}, status=status.HTTP_404_NOT_FOUND)


class SweetRestockView(APIView):
    """
    @description: Restock a sweet (Admin only)
    @input_json: {"quantity": <int>}
    """
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        try:
            sweet = Sweet.objects.get(pk=pk)
            quantity_to_add = request.data.get('quantity', 0)
            if quantity_to_add <= 0:
                return Response({"error": "Quantity must be greater than 0"}, status=status.HTTP_400_BAD_REQUEST)
            sweet.quantity += int(quantity_to_add)
            sweet.save()
            return Response({"message": "Sweet restocked successfully"}, status=status.HTTP_200_OK)
        except Sweet.DoesNotExist:
            return Response({"error": "Sweet not found"}, status=status.HTTP_404_NOT_FOUND)


class SweetSearchView(generics.ListAPIView):
    """
    @description: Search sweets based on name, category, min_price, max_price
    @input_query: ?name=&category=&min_price=&max_price=
    """
    serializer_class = SweetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = Sweet.objects.all()
        name = self.request.query_params.get('name')
        category = self.request.query_params.get('category')
        min_price = self.request.query_params.get('min_price')
        max_price = self.request.query_params.get('max_price')
        if name:
            queryset = queryset.filter(name__icontains=name)
        if category:
            queryset = queryset.filter(category=category)
        if min_price:
            queryset = queryset.filter(price__gte=min_price)
        if max_price:
            queryset = queryset.filter(price__lte=max_price)
        return queryset.order_by('name')
