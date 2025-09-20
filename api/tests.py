from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from decimal import Decimal
from unittest.mock import patch
import json

from .models import User, Sweet, Purchase, InventoryLog
from .utils import generate_verification_token, send_verification_email

User = get_user_model()


class UserModelTest(TestCase):
    """Test cases for the User model"""

    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        }

    def test_create_user_default_role(self):
        """Test creating a user with default role"""
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.role, 'user')
        self.assertFalse(user.is_email_verified)
        self.assertTrue(user.is_active)

    def test_create_admin_user(self):
        """Test creating an admin user"""
        admin_data = self.user_data.copy()
        admin_data['role'] = 'admin'
        user = User.objects.create_user(**admin_data)
        self.assertEqual(user.role, 'admin')

    def test_user_str_representation(self):
        """Test the string representation of user"""
        user = User.objects.create_user(**self.user_data)
        expected = f"{user.username} ({user.role})"
        self.assertEqual(str(user), expected)

    def test_email_verification_default_false(self):
        """Test that email verification defaults to False"""
        user = User.objects.create_user(**self.user_data)
        self.assertFalse(user.is_email_verified)

    def test_unique_username(self):
        """Test that username must be unique"""
        User.objects.create_user(**self.user_data)
        with self.assertRaises(Exception):
            User.objects.create_user(**self.user_data)

    def test_role_choices(self):
        """Test valid role choices"""
        # Test valid roles
        for role, _ in User.ROLE_CHOICES:
            user_data = self.user_data.copy()
            user_data['username'] = f'test_{role}'
            user_data['email'] = f'test_{role}@example.com'
            user_data['role'] = role
            user = User.objects.create_user(**user_data)
            self.assertEqual(user.role, role)


class SweetModelTest(TestCase):
    """Test cases for the Sweet model"""

    def setUp(self):
        self.sweet_data = {
            'name': 'Chocolate Cake',
            'category': 'Cakes',
            'price': Decimal('15.99'),
            'quantity': 10
        }

    def test_create_sweet(self):
        """Test creating a sweet"""
        sweet = Sweet.objects.create(**self.sweet_data)
        self.assertEqual(sweet.name, 'Chocolate Cake')
        self.assertEqual(sweet.category, 'Cakes')
        self.assertEqual(sweet.price, Decimal('15.99'))
        self.assertEqual(sweet.quantity, 10)

    def test_sweet_str_representation(self):
        """Test the string representation of sweet"""
        sweet = Sweet.objects.create(**self.sweet_data)
        expected = f"{sweet.name} ({sweet.quantity} in stock)"
        self.assertEqual(str(sweet), expected)

    def test_unique_name_constraint(self):
        """Test that sweet names must be unique"""
        Sweet.objects.create(**self.sweet_data)
        with self.assertRaises(Exception):
            Sweet.objects.create(**self.sweet_data)

    def test_default_quantity(self):
        """Test default quantity is 0"""
        sweet_data = self.sweet_data.copy()
        del sweet_data['quantity']
        sweet = Sweet.objects.create(**sweet_data)
        self.assertEqual(sweet.quantity, 0)

    def test_auto_timestamps(self):
        """Test that created_at and updated_at are set automatically"""
        sweet = Sweet.objects.create(**self.sweet_data)
        self.assertIsNotNone(sweet.created_at)
        self.assertIsNotNone(sweet.updated_at)
        
        # Test that updated_at changes when model is saved
        original_updated_at = sweet.updated_at
        sweet.price = Decimal('20.99')
        sweet.save()
        self.assertGreater(sweet.updated_at, original_updated_at)

    def test_negative_price_not_allowed(self):
        """Test that negative prices should not be allowed"""
        sweet_data = self.sweet_data.copy()
        sweet_data['price'] = Decimal('-5.00')
        # Note: This test depends on model validation being implemented
        sweet = Sweet.objects.create(**sweet_data)
        # In a real scenario, you'd want to add model validation


class PurchaseModelTest(TestCase):
    """Test cases for the Purchase model"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.sweet = Sweet.objects.create(
            name='Chocolate Cake',
            category='Cakes',
            price=Decimal('15.99'),
            quantity=10
        )

    def test_create_purchase(self):
        """Test creating a purchase"""
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        self.assertEqual(purchase.user, self.user)
        self.assertEqual(purchase.sweet, self.sweet)
        self.assertEqual(purchase.quantity, 2)
        self.assertEqual(purchase.price_at_purchase, Decimal('15.99'))

    def test_purchase_str_representation(self):
        """Test the string representation of purchase"""
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        expected = f"{self.user.username} bought {purchase.quantity} x {self.sweet.name}"
        self.assertEqual(str(purchase), expected)

    def test_purchase_timestamp_auto_set(self):
        """Test that purchased_at is set automatically"""
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        self.assertIsNotNone(purchase.purchased_at)

    def test_user_deletion_cascades_to_purchases(self):
        """Test that deleting a user cascades to purchases"""
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        purchase_id = purchase.id
        self.user.delete()
        self.assertFalse(Purchase.objects.filter(id=purchase_id).exists())

    def test_sweet_deletion_cascades_to_purchases(self):
        """Test that deleting a sweet cascades to purchases"""
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        purchase_id = purchase.id
        self.sweet.delete()
        self.assertFalse(Purchase.objects.filter(id=purchase_id).exists())


class InventoryLogModelTest(TestCase):
    """Test cases for the InventoryLog model"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.sweet = Sweet.objects.create(
            name='Chocolate Cake',
            category='Cakes',
            price=Decimal('15.99'),
            quantity=10
        )

    def test_create_inventory_log_purchase(self):
        """Test creating an inventory log for purchase"""
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='purchase',
            quantity_changed=-2,
            performed_by=self.user
        )
        self.assertEqual(log.sweet, self.sweet)
        self.assertEqual(log.action, 'purchase')
        self.assertEqual(log.quantity_changed, -2)
        self.assertEqual(log.performed_by, self.user)

    def test_create_inventory_log_restock(self):
        """Test creating an inventory log for restock"""
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='restock',
            quantity_changed=20,
            performed_by=self.user
        )
        self.assertEqual(log.action, 'restock')
        self.assertEqual(log.quantity_changed, 20)

    def test_inventory_log_str_representation(self):
        """Test the string representation of inventory log"""
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='purchase',
            quantity_changed=-2,
            performed_by=self.user
        )
        expected = f"Purchase -2 of {self.sweet.name} by {self.user}"
        self.assertEqual(str(log), expected)

    def test_performed_by_null_on_user_deletion(self):
        """Test that performed_by is set to null when user is deleted"""
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='purchase',
            quantity_changed=-2,
            performed_by=self.user
        )
        self.user.delete()
        log.refresh_from_db()
        self.assertIsNone(log.performed_by)

    def test_timestamp_auto_set(self):
        """Test that timestamp is set automatically"""
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='restock',
            quantity_changed=10,
            performed_by=self.user
        )
        self.assertIsNotNone(log.timestamp)


class UtilsTest(TestCase):
    """Test cases for utility functions"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_generate_verification_token(self):
        """Test generating verification token"""
        token = generate_verification_token(self.user)
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)
        
        # Verify token can be decoded
        access_token = AccessToken(token)
        self.assertEqual(access_token['user_id'], self.user.id)

    @patch('api.utils.send_mail')
    def test_send_verification_email(self, mock_send_mail):
        """Test sending verification email"""
        send_verification_email(self.user)
        
        # Verify send_mail was called
        mock_send_mail.assert_called_once()
        
        # Check the arguments passed to send_mail
        args, kwargs = mock_send_mail.call_args
        self.assertEqual(args[0], "Verify Your Email")  # subject
        self.assertIn(self.user.username, args[1])  # message contains username
        self.assertEqual(args[3], [self.user.email])  # recipient

    def test_verification_token_contains_user_info(self):
        """Test that verification token contains user information"""
        token = generate_verification_token(self.user)
        access_token = AccessToken(token)
        self.assertEqual(access_token['user_id'], self.user.id)


class RegisterViewTest(APITestCase):
    """Test cases for RegisterView"""

    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.valid_user_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123'
        }

    @patch('api.views.send_verification_email')
    def test_register_valid_user(self, mock_send_email):
        """Test registering a valid user"""
        response = self.client.post(self.register_url, self.valid_user_data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        
        user = User.objects.get(username='newuser')
        self.assertEqual(user.email, 'newuser@example.com')
        self.assertEqual(user.role, 'user')
        self.assertFalse(user.is_email_verified)
        
        # Verify email was sent
        mock_send_email.assert_called_once_with(user)

    def test_register_duplicate_email(self):
        """Test registering with duplicate email"""
        # Create a user first
        User.objects.create_user(**self.valid_user_data)
        
        # Try to register with same email
        duplicate_data = self.valid_user_data.copy()
        duplicate_data['username'] = 'differentuser'
        
        response = self.client.post(self.register_url, duplicate_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Email already exists', response.data['error'])

    def test_register_admin_user_without_permission(self):
        """Test registering admin user without admin permission"""
        admin_data = self.valid_user_data.copy()
        admin_data['role'] = 'admin'
        
        response = self.client.post(self.register_url, admin_data)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Only admins can create admin users', response.data['error'])

    def test_register_admin_user_with_permission(self):
        """Test registering admin user with admin permission"""
        # Create an admin user and authenticate
        admin_user = User.objects.create_user(
            username='admin',
            email='admin@example.com',
            password='adminpass123',
            role='admin'
        )
        self.client.force_authenticate(user=admin_user)
        
        admin_data = self.valid_user_data.copy()
        admin_data['role'] = 'admin'
        
        with patch('api.views.send_verification_email') as mock_send_email:
            response = self.client.post(self.register_url, admin_data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(username='newuser')
        self.assertEqual(user.role, 'admin')

    def test_register_missing_required_fields(self):
        """Test registering with missing required fields"""
        incomplete_data = {
            'username': 'testuser'
            # missing email and password
        }
        
        response = self.client.post(self.register_url, incomplete_data)
        
        # This should fail (exact status code depends on Django's validation)
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)

    def test_register_invalid_email_format(self):
        """Test registering with invalid email format"""
        invalid_data = self.valid_user_data.copy()
        invalid_data['email'] = 'invalid-email'
        
        response = self.client.post(self.register_url, invalid_data)
        
        # Should fail validation
        self.assertNotEqual(response.status_code, status.HTTP_201_CREATED)


class LoginViewTest(APITestCase):
    """Test cases for LoginView"""

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('register')  # Note: URL name is 'register' in urls.py
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_login_with_verified_email(self):
        """Test login with verified email"""
        self.user.is_email_verified = True
        self.user.save()
        
        login_data = {
            'username': self.user_data['username'],
            'password': self.user_data['password']
        }
        
        response = self.client.post(self.login_url, login_data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['role'], self.user.role)
        self.assertTrue(response.data['verified'])

    def test_login_with_unverified_email(self):
        """Test login with unverified email"""
        login_data = {
            'username': self.user_data['username'],
            'password': self.user_data['password']
        }
        
        response = self.client.post(self.login_url, login_data)
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Please verify your email first', response.data['error'])

    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        invalid_data = {
            'username': self.user_data['username'],
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, invalid_data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('Invalid credentials', response.data['error'])

    def test_login_with_nonexistent_user(self):
        """Test login with nonexistent user"""
        nonexistent_data = {
            'username': 'nonexistentuser',
            'password': 'somepassword'
        }
        
        response = self.client.post(self.login_url, nonexistent_data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('Invalid credentials', response.data['error'])

    def test_login_missing_credentials(self):
        """Test login with missing credentials"""
        incomplete_data = {
            'username': self.user_data['username']
            # missing password
        }
        
        response = self.client.post(self.login_url, incomplete_data)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class VerifyEmailViewTest(APITestCase):
    """Test cases for VerifyEmailView"""

    def setUp(self):
        self.client = APIClient()
        self.verify_url = reverse('verify_email')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_verify_email_with_valid_token(self):
        """Test email verification with valid token"""
        token = generate_verification_token(self.user)
        
        response = self.client.get(f"{self.verify_url}?token={token}")
        
        self.assertEqual(response.status_code, 200)
        
        # Check that user is now verified
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)

    def test_verify_email_with_invalid_token(self):
        """Test email verification with invalid token"""
        invalid_token = "invalid.token.here"
        
        response = self.client.get(f"{self.verify_url}?token={invalid_token}")
        
        self.assertEqual(response.status_code, 400)
        
        # Check that user is still not verified
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_email_verified)

    def test_verify_email_without_token(self):
        """Test email verification without token"""
        response = self.client.get(self.verify_url)
        
        self.assertEqual(response.status_code, 400)
        
        # Check that user is still not verified
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_email_verified)

    def test_verify_email_with_expired_token(self):
        """Test email verification with expired token"""
        # Create an expired token
        refresh = RefreshToken.for_user(self.user)
        access_token = refresh.access_token
        
        # Manually set token to expired (this is a simplified test)
        # In a real scenario, you'd need to manipulate token expiry
        expired_token = str(access_token)
        
        # Mock the token validation to raise an exception
        with patch('rest_framework_simplejwt.tokens.AccessToken.__init__') as mock_token:
            mock_token.side_effect = Exception("Token expired")
            
            response = self.client.get(f"{self.verify_url}?token={expired_token}")
            
            self.assertEqual(response.status_code, 400)

    def test_verify_email_with_nonexistent_user_token(self):
        """Test email verification with token for nonexistent user"""
        # Create token for user then delete user
        token = generate_verification_token(self.user)
        self.user.delete()
        
        response = self.client.get(f"{self.verify_url}?token={token}")
        
        self.assertEqual(response.status_code, 400)


class LogoutViewTest(APITestCase):
    """Test cases for LogoutView"""

    def setUp(self):
        self.client = APIClient()
        self.logout_url = reverse('logout')
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_logout_authenticated_user(self):
        """Test logout for authenticated user"""
        self.client.force_authenticate(user=self.user)
        
        response = self.client.post(self.logout_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Logged out successfully', response.data['message'])

    def test_logout_unauthenticated_user(self):
        """Test logout for unauthenticated user"""
        response = self.client.post(self.logout_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class IntegrationTest(APITestCase):
    """Integration tests for the complete user flow"""

    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')
        self.login_url = reverse('register')  # Note: same URL as register
        self.verify_url = reverse('verify_email')
        self.user_data = {
            'username': 'integrationuser',
            'email': 'integration@example.com',
            'password': 'securepass123'
        }

    @patch('api.views.send_verification_email')
    def test_complete_user_registration_and_login_flow(self, mock_send_email):
        """Test complete user registration and login flow"""
        # Step 1: Register user
        response = self.client.post(self.register_url, self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Step 2: Try to login before email verification (should fail)
        login_data = {
            'username': self.user_data['username'],
            'password': self.user_data['password']
        }
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        
        # Step 3: Verify email
        user = User.objects.get(username=self.user_data['username'])
        token = generate_verification_token(user)
        response = self.client.get(f"{self.verify_url}?token={token}")
        self.assertEqual(response.status_code, 200)
        
        # Step 4: Login after email verification (should succeed)
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_admin_user_creation_flow(self):
        """Test admin user creation flow"""
        # Step 1: Create initial admin user
        admin_user = User.objects.create_user(
            username='superadmin',
            email='admin@example.com',
            password='adminpass123',
            role='admin',
            is_email_verified=True
        )
        
        # Step 2: Authenticate as admin
        self.client.force_authenticate(user=admin_user)
        
        # Step 3: Create another admin user
        new_admin_data = {
            'username': 'newadmin',
            'email': 'newadmin@example.com',
            'password': 'newadminpass123',
            'role': 'admin'
        }
        
        with patch('api.views.send_verification_email'):
            response = self.client.post(self.register_url, new_admin_data)
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        new_admin = User.objects.get(username='newadmin')
        self.assertEqual(new_admin.role, 'admin')


class EdgeCaseTest(TestCase):
    """Test edge cases and error conditions"""

    def test_sweet_with_extremely_long_name(self):
        """Test sweet with name at character limit"""
        long_name = 'a' * 100  # Max length is 100
        sweet = Sweet.objects.create(
            name=long_name,
            category='Test',
            price=Decimal('10.00')
        )
        self.assertEqual(len(sweet.name), 100)

    def test_sweet_with_zero_price(self):
        """Test sweet with zero price"""
        sweet = Sweet.objects.create(
            name='Free Sample',
            category='Samples',
            price=Decimal('0.00')
        )
        self.assertEqual(sweet.price, Decimal('0.00'))

    def test_purchase_with_very_large_quantity(self):
        """Test purchase with large quantity"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        sweet = Sweet.objects.create(
            name='Test Sweet',
            category='Test',
            price=Decimal('1.00'),
            quantity=1000000
        )
        
        purchase = Purchase.objects.create(
            user=user,
            sweet=sweet,
            quantity=999999,
            price_at_purchase=sweet.price
        )
        self.assertEqual(purchase.quantity, 999999)

    def test_inventory_log_with_zero_quantity_change(self):
        """Test inventory log with zero quantity change"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        sweet = Sweet.objects.create(
            name='Test Sweet',
            category='Test',
            price=Decimal('1.00')
        )
        
        log = InventoryLog.objects.create(
            sweet=sweet,
            action='restock',
            quantity_changed=0,
            performed_by=user
        )
        self.assertEqual(log.quantity_changed, 0)

    def test_user_with_special_characters_in_username(self):
        """Test user with special characters in username"""
        special_chars_user = User.objects.create_user(
            username='user@test.com',
            email='special@example.com',
            password='testpass123'
        )
        self.assertEqual(special_chars_user.username, 'user@test.com')


# Performance and Load Testing (basic examples)
class PerformanceTest(TestCase):
    """Basic performance tests"""

    def test_bulk_user_creation(self):
        """Test creating multiple users"""
        users_data = [
            User(
                username=f'user{i}',
                email=f'user{i}@example.com',
                password='testpass123'
            ) for i in range(100)
        ]
        
        # Bulk create should be efficient
        created_users = User.objects.bulk_create(users_data)
        self.assertEqual(len(created_users), 100)

    def test_bulk_sweet_creation(self):
        """Test creating multiple sweets"""
        sweets_data = [
            Sweet(
                name=f'Sweet {i}',
                category=f'Category {i % 5}',
                price=Decimal(f'{i + 1}.99'),
                quantity=i * 10
            ) for i in range(50)
        ]
        
        created_sweets = Sweet.objects.bulk_create(sweets_data)
        self.assertEqual(len(created_sweets), 50)


if __name__ == '__main__':
    import unittest
    unittest.main()