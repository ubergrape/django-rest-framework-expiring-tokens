"""Tests for Django Rest Framework Session Authentication package."""
from datetime import timedelta
from time import sleep

from django.contrib.auth.models import User

from rest_framework import status
from django.urls import reverse
from rest_framework.test import APITestCase

from rest_framework_expiring_authtoken.models import ExpiringToken
from rest_framework.authtoken.models import Token


class ObtainExpiringTokenViewTestCase(APITestCase):

    """Tests for the Obtain Expiring Token View."""

    def setUp(self):
        """Create a user."""
        self.username = 'test'
        self.email = 'test@test.com'
        self.password = 'test'
        self.url = reverse('auth-token')
        self.user = User.objects.create_user(
            username=self.username,
            email=self.email,
            password=self.password
        )

    def test_post(self):
        """Check token can be obtained by posting credentials."""
        token = ExpiringToken.objects.create(user=self.user)

        response = self.client.post(
            self.url,
            {
                'username': self.username,
                'password': self.password
            }
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check the response contains the token key.
        self.assertEqual(token.key, response.data['token'])

    def test_post_create_token(self):
        """Check token is created if none exists."""
        response = self.client.post(
            self.url,
            {
                'username': self.username,
                'password': self.password
            }
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check token was created and the response contains the token key.
        token = ExpiringToken.objects.first()
        self.assertEqual(token.user, self.user)
        self.assertEqual(response.data['token'], token.key)

    def test_post_no_credentials(self):
        """Check POST request with no credentials fails."""
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data,
            {
                'username': ['This field is required.'],
                'password': ['This field is required.']
            }
        )

    def test_post_wrong_credentials(self):
        """Check POST request with wrong credentials fails."""
        response = self.client.post(
            self.url,
            {
                'username': self.username,
                'password': 'wrong'
            }
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data,
            {
                'non_field_errors': [
                    'Unable to log in with provided credentials.'
                ]
            }
        )

    def test_post_expired_token(self):
        """Check that expired tokens are replaced."""
        token = ExpiringToken.objects.create(user=self.user)
        key_1 = token.key

        # Make the first token expire.
        with self.settings(EXPIRING_TOKEN_LIFESPAN=timedelta(milliseconds=1)):
            sleep(0.001)
            response = self.client.post(
                self.url,
                {
                    'username': self.username,
                    'password': self.password
                }
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check token was renewed and the response contains the token key.
        token = ExpiringToken.objects.first()
        key_2 = token.key
        self.assertEqual(token.user, self.user)
        self.assertEqual(response.data['token'], token.key)
        self.assertTrue(key_1 != key_2)

    def test_delete_token(self):
        _ = ExpiringToken.objects.create(user=self.user)
        self.assertEqual(ExpiringToken.objects.count(), 1)
        
        response = self.client.delete(
            '/auth-token/',
            {
                'username': self.username,
                'password': self.password
            }
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(ExpiringToken.objects.count(), 0)

    def test_two_tokens(self):
        """
        tests if the user can have one long and one short living token.
        """
        self.assertEqual(ExpiringToken.objects.count(), 0)
        self.assertEqual(Token.objects.count(), 0)

        _ = ExpiringToken.objects.get_or_create(user=self.user)
        self.assertEqual(ExpiringToken.objects.count(), 1)
        self.assertEqual(Token.objects.count(), 0)

        _ = Token.objects.get_or_create(user=self.user)
        self.assertEqual(ExpiringToken.objects.count(), 1)
        self.assertEqual(Token.objects.count(), 1)
