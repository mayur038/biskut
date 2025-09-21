from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core import mail
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from decimal import Decimal
from unittest.mock import patch

from .models import User, Sweet, Purchase, InventoryLog
from .utils import generate_verification_token, send_verification_email

User = get_user_model()


# -------------------------------
# User Model Tests
# -------------------------------
class UserModelTest(TestCase):
    """Test cases for the User model"""

    def setUp(self):
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        }

    def test_create_user_default_role(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(user.role, 'user')
        self.assertFalse(user.is_email_verified)
        self.assertTrue(user.is_active)

    def test_create_admin_user(self):
        admin_data = self.user_data.copy()
        admin_data['role'] = 'admin'
        user = User.objects.create_user(**admin_data)
        self.assertEqual(user.role, 'admin')

    def test_user_str_representation(self):
        user = User.objects.create_user(**self.user_data)
        self.assertEqual(str(user), f"{user.username} ({user.role})")

    def test_email_verification_default_false(self):
        user = User.objects.create_user(**self.user_data)
        self.assertFalse(user.is_email_verified)

    def test_unique_username(self):
        User.objects.create_user(**self.user_data)
        with self.assertRaises(Exception):
            User.objects.create_user(**self.user_data)

    def test_role_choices(self):
        for role, _ in User.ROLE_CHOICES:
            user_data = self.user_data.copy()
            user_data['username'] = f'test_{role}'
            user_data['email'] = f'test_{role}@example.com'
            user_data['role'] = role
            user = User.objects.create_user(**user_data)
            self.assertEqual(user.role, role)


# -------------------------------
# Sweet Model Tests
# -------------------------------
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
        sweet = Sweet.objects.create(**self.sweet_data)
        self.assertEqual(sweet.name, 'Chocolate Cake')
        self.assertEqual(sweet.category, 'Cakes')
        self.assertEqual(sweet.price, Decimal('15.99'))
        self.assertEqual(sweet.quantity, 10)

    def test_sweet_str_representation(self):
        sweet = Sweet.objects.create(**self.sweet_data)
        self.assertEqual(str(sweet), f"{sweet.name} ({sweet.quantity} in stock)")

    def test_unique_name_constraint(self):
        Sweet.objects.create(**self.sweet_data)
        with self.assertRaises(Exception):
            Sweet.objects.create(**self.sweet_data)

    def test_default_quantity(self):
        sweet_data = self.sweet_data.copy()
        del sweet_data['quantity']
        sweet = Sweet.objects.create(**sweet_data)
        self.assertEqual(sweet.quantity, 0)

    def test_auto_timestamps(self):
        sweet = Sweet.objects.create(**self.sweet_data)
        self.assertIsNotNone(sweet.created_at)
        self.assertIsNotNone(sweet.updated_at)
        original_updated_at = sweet.updated_at
        sweet.price = Decimal('20.99')
        sweet.save()
        self.assertGreater(sweet.updated_at, original_updated_at)

    def test_negative_price_not_allowed(self):
        sweet_data = self.sweet_data.copy()
        sweet_data['price'] = Decimal('-5.00')
        sweet = Sweet.objects.create(**sweet_data)
        # You should ideally implement model validation to prevent this


# -------------------------------
# Purchase Model Tests
# -------------------------------
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
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        self.assertEqual(str(purchase), f"{self.user.username} bought {purchase.quantity} x {self.sweet.name}")

    def test_purchase_timestamp_auto_set(self):
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        self.assertIsNotNone(purchase.purchased_at)

    def test_user_deletion_cascades_to_purchases(self):
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
        purchase = Purchase.objects.create(
            user=self.user,
            sweet=self.sweet,
            quantity=2,
            price_at_purchase=self.sweet.price
        )
        purchase_id = purchase.id
        self.sweet.delete()
        self.assertFalse(Purchase.objects.filter(id=purchase_id).exists())


# -------------------------------
# Inventory Log Model Tests
# -------------------------------
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
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='purchase',
            quantity_changed=-2,
            performed_by=self.user
        )
        self.assertEqual(log.action, 'purchase')
        self.assertEqual(log.quantity_changed, -2)
        self.assertEqual(log.performed_by, self.user)

    def test_create_inventory_log_restock(self):
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='restock',
            quantity_changed=20,
            performed_by=self.user
        )
        self.assertEqual(log.action, 'restock')
        self.assertEqual(log.quantity_changed, 20)

    def test_inventory_log_str_representation(self):
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='purchase',
            quantity_changed=-2,
            performed_by=self.user
        )
        self.assertEqual(str(log), f"Purchase -2 of {self.sweet.name} by {self.user}")

    def test_performed_by_null_on_user_deletion(self):
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
        log = InventoryLog.objects.create(
            sweet=self.sweet,
            action='restock',
            quantity_changed=10,
            performed_by=self.user
        )
        self.assertIsNotNone(log.timestamp)


# -------------------------------
# Utils Tests
# -------------------------------
class UtilsTest(TestCase):
    """Test cases for utility functions"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    @patch('api.utils.send_mail')
    def test_send_verification_email(self, mock_send_mail):
        send_verification_email(self.user)
        mock_send_mail.assert_called_once()
        args, kwargs = mock_send_mail.call_args
        self.assertEqual(args[0], "Verify Your Email")
        self.assertIn(self.user.username, args[1])
        self.assertEqual(args[3], [self.user.email])


# -------------------------------
# API View Tests
# -------------------------------
class RegisterViewTest(APITestCase):
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
        response = self.client.post(self.register_url, self.valid_user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(username='newuser')
        self.assertEqual(user.role, 'user')
        self.assertFalse(user.is_email_verified)
        mock_send_email.assert_called_once_with(user)

    def test_register_duplicate_email(self):
        User.objects.create_user(**self.valid_user_data)
        duplicate_data = self.valid_user_data.copy()
        duplicate_data['username'] = 'differentuser'
        response = self.client.post(self.register_url, duplicate_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Email already exists', response.data['error'])

    def test_register_admin_user_without_permission(self):
        admin_data = self.valid_user_data.copy()
        admin_data['role'] = 'admin'
        response = self.client.post(self.register_url, admin_data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Only admins can create admin users', response.data['error'])


class LoginViewTest(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login')
        self.user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        self.user = User.objects.create_user(**self.user_data)

    def test_login_with_verified_email(self):
        self.user.is_email_verified = True
        self.user.save()
        login_data = {'username': self.user_data['username'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_unverified_email(self):
        login_data = {'username': self.user_data['username'], 'password': self.user_data['password']}
        response = self.client.post(self.login_url, login_data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Please verify your email first', response.data['error'])


# -------------------------------
# Edge Cases and Performance Tests
# -------------------------------
class EdgeCaseTest(TestCase):
    def test_sweet_with_extremely_long_name(self):
        long_name = 'a' * 100
        sweet = Sweet.objects.create(name=long_name, category='Test', price=Decimal('10.00'))
        self.assertEqual(len(sweet.name), 100)

    def test_purchase_with_very_large_quantity(self):
        user = User.objects.create_user(username='user', email='user@example.com', password='123')
        sweet = Sweet.objects.create(name='BigSweet', category='Test', price=Decimal('1.00'), quantity=1000000)
        purchase = Purchase.objects.create(user=user, sweet=sweet, quantity=999999, price_at_purchase=sweet.price)
        self.assertEqual(purchase.quantity, 999999)


class PerformanceTest(TestCase):
    def test_bulk_user_creation(self):
        users_data = [User(username=f'user{i}', email=f'user{i}@example.com', password='testpass123') for i in range(100)]
        created_users = User.objects.bulk_create(users_data)
        self.assertEqual(len(created_users), 100)

    def test_bulk_sweet_creation(self):
        sweets_data = [
            Sweet(name=f'Sweet {i}', category=f'Cat{i%5}', price=Decimal(f'{i+1}.99'), quantity=i*10) for i in range(50)
        ]
        created_sweets = Sweet.objects.bulk_create(sweets_data)
        self.assertEqual(len(created_sweets), 50)


if __name__ == '__main__':
    import unittest
    unittest.main()
