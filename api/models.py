from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# -----------------------------
# Custom User Model
# -----------------------------
class User(AbstractUser):
    ROLE_CHOICES = (
        ('user', 'User'),
        ('admin', 'Admin'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    is_email_verified = models.BooleanField(default=False)
    def __str__(self):
        return f"{self.username} ({self.role})"


# -----------------------------
# Sweet Model
# -----------------------------
class Sweet(models.Model):
    name = models.CharField(max_length=100, unique=True)
    category = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    quantity = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.quantity} in stock)"


# -----------------------------
# Purchase Model
# -----------------------------
class Purchase(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='purchases')
    sweet = models.ForeignKey(Sweet, on_delete=models.CASCADE, related_name='purchases')
    quantity = models.PositiveIntegerField()
    price_at_purchase = models.DecimalField(max_digits=10, decimal_places=2)
    purchased_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.user.username} bought {self.quantity} x {self.sweet.name}"


# -----------------------------
# Inventory Log Model
# -----------------------------
class InventoryLog(models.Model):
    ACTION_CHOICES = (
        ('purchase', 'Purchase'),
        ('restock', 'Restock'),
    )

    sweet = models.ForeignKey(Sweet, on_delete=models.CASCADE, related_name='inventory_logs')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    quantity_changed = models.IntegerField()
    performed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='inventory_actions')
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.action.title()} {self.quantity_changed} of {self.sweet.name} by {self.performed_by}"
