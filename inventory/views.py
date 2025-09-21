"""
@description: API views for Sweet Shop purchase, restock, and current user info
@author: Mayur Gohil
@date_of_modification: 22-Sep-2025
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.shortcuts import get_object_or_404

from api.models import Sweet, Purchase, InventoryLog
from .serializer import PurchaseSerializer, RestockSerializer
from .permissions import IsAdminUser


# ---------------------------------------------
# Purchase Sweet (Authenticated users)
# ---------------------------------------------
class SweetPurchaseView(APIView):
    """
    @description: API for purchasing sweets. Decreases stock, logs inventory, and creates a purchase record.
    @input_json: {"quantity": <int>}
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk):
        sweet = get_object_or_404(Sweet, pk=pk)
        serializer = PurchaseSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        quantity_to_buy = serializer.validated_data['quantity']

        if quantity_to_buy > sweet.quantity:
            return Response(
                {"error": f"Not enough stock. Available quantity: {sweet.quantity}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        price_at_purchase = sweet.price * quantity_to_buy

        # Create Purchase record
        Purchase.objects.create(
            user=request.user,
            sweet=sweet,
            quantity=quantity_to_buy,
            price_at_purchase=price_at_purchase
        )

        # Update stock
        sweet.quantity -= quantity_to_buy
        sweet.save()

        # Log inventory action
        InventoryLog.objects.create(
            sweet=sweet,
            action='purchase',
            quantity_changed=quantity_to_buy,
            performed_by=request.user
        )

        return Response({
            "message": f"Purchased {quantity_to_buy} x {sweet.name}",
            "total_price": price_at_purchase,
            "current_quantity": sweet.quantity
        }, status=status.HTTP_200_OK)


# ---------------------------------------------
# Restock Sweet (Admin only)
# ---------------------------------------------
class SweetRestockView(APIView):
    """
    @description: API for admin to restock sweets. Updates stock and logs inventory action.
    @input_json: {"quantity": <int>}
    """
    permission_classes = [IsAdminUser]

    def post(self, request, pk):
        sweet = get_object_or_404(Sweet, pk=pk)
        serializer = RestockSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        quantity_to_add = serializer.validated_data['quantity']

        # Update stock
        sweet.quantity += quantity_to_add
        sweet.save()

        # Log inventory action
        InventoryLog.objects.create(
            sweet=sweet,
            action='restock',
            quantity_changed=quantity_to_add,
            performed_by=request.user
        )

        return Response({
            "message": f"Restocked {quantity_to_add} x {sweet.name}",
            "current_quantity": sweet.quantity
        }, status=status.HTTP_200_OK)


# ---------------------------------------------
# Current User Profile
# ---------------------------------------------
class CurrentUserView(APIView):
    """
    @description: API to fetch details of currently authenticated user.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "date_joined": user.date_joined,
            "verified": user.is_email_verified
        }, status=status.HTTP_200_OK)
