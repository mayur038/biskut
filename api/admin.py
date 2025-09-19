from django.contrib import admin
from .models import User, Sweet, Purchase, InventoryLog

# Register your models here
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'role', 'is_email_verified', 'is_staff', 'is_active')
    list_filter = ('role', 'is_email_verified', 'is_staff', 'is_active')
    search_fields = ('username', 'email')


@admin.register(Sweet)
class SweetAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'price', 'quantity', 'created_at', 'updated_at')
    list_filter = ('category',)
    search_fields = ('name',)


@admin.register(Purchase)
class PurchaseAdmin(admin.ModelAdmin):
    list_display = ('user', 'sweet', 'quantity', 'price_at_purchase', 'purchased_at')
    list_filter = ('purchased_at',)
    search_fields = ('user__username', 'sweet__name')


@admin.register(InventoryLog)
class InventoryLogAdmin(admin.ModelAdmin):
    list_display = ('sweet', 'action', 'quantity_changed', 'performed_by', 'timestamp')
    list_filter = ('action', 'timestamp')
    search_fields = ('sweet__name', 'performed_by__username')
