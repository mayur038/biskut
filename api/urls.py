from django.urls import path
from .views import *
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # Sweet Endpoints
    path('', SweetListView.as_view(), name='sweet-list'),
    path('create/', SweetCreateView.as_view(), name='sweet-create'),
    path('<int:pk>/update/', SweetUpdateView.as_view(), name='sweet-update'),
    path('<int:pk>/delete/', SweetDeleteView.as_view(), name='sweet-delete'),

]
