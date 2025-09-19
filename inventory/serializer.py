from rest_framework import serializers

# -----------------------------
# Purchase Serializer
# -----------------------------
class PurchaseSerializer(serializers.Serializer):
    quantity = serializers.IntegerField(min_value=1)

# -----------------------------
# Restock Serializer
# -----------------------------
class RestockSerializer(serializers.Serializer):
    quantity = serializers.IntegerField(min_value=1)
