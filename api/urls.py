from django.urls import path
from .views import *
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # Sweet Endpoints
    path('sweets/', SweetListView.as_view(), name='sweet-list'),
    path('sweets/create/', SweetCreateView.as_view(), name='sweet-create'),
    path('sweets/<int:pk>/', SweetUpdateView.as_view(), name='sweet-update'),
    path('sweets/<int:pk>/delete/', SweetDeleteView.as_view(), name='sweet-delete'),
    path('sweets/<int:pk>/purchase/', SweetPurchaseView.as_view(), name='sweet-purchase'),
    path('sweets/<int:pk>/restock/', SweetRestockView.as_view(), name='sweet-restock'),
    path('sweets/search/', SweetSearchView.as_view(), name='sweet-search'),
]
