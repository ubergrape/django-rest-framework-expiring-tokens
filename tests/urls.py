"""URL conf for testing Expiring Tokens."""
from django.conf.urls import url

from rest_framework_expiring_authtoken.views import auth_token_view

urlpatterns = [
    url(r'^auth-token/$', auth_token_view, name='auth-token'),
]
