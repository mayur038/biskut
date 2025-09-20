from django.urls import path
from .views import SweetPurchaseView, SweetRestockView, CurrentUserView

urlpatterns = [
    path('<int:pk>/purchase', SweetPurchaseView.as_view(), name='sweet-purchase'),
    path('<int:pk>/restock', SweetRestockView.as_view(), name='sweet-restock'),
    path('users/me', CurrentUserView.as_view(), name='current-user'),
]
