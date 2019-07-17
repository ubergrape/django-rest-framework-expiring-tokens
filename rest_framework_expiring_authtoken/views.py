"""Utility views for Expiring Tokens.

Classes:
    ObtainExpiringAuthToken: View to provide tokens to clients.
"""
import base64
from django.conf import settings
from django.http import Http404
from django.utils.translation import ugettext_lazy as _
from functools import reduce
from rest_framework import serializers
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_204_NO_CONTENT
from rest_framework_expiring_authtoken.models import ExpiringToken


class AuthTokenOTPSerializer(AuthTokenSerializer):
    otp = serializers.CharField(label=_("OTP"),
                                trim_whitespace=True,
                                required=False)

    def __init__(self, *args, **kwargs):
        if "auth_class" in kwargs:
            self.auth_class = kwargs.pop("auth_class")
        if "request" in kwargs:
            self.request = kwargs.pop("request")
        else:
            self.request = self.context.get('request')
        super().__init__(*args, **kwargs)

    def validate(self, attrs):
        # we set the credentials in the request.META headers
        # (as the rest_framework.authentication expects)
        username = attrs.get("username")
        password = attrs.get("password")
        if not username and password:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        b64_auth_str = base64.b64encode("{}:{}".format(
            username, password).encode("utf-8"))

        auth_str = "Basic {}".format(b64_auth_str.decode("utf-8"))
        self.request.META.update({'HTTP_AUTHORIZATION': auth_str})

        if "otp" in attrs:
            # If an OTP was provided, we set the otp in the request's GET
            self.request.GET._mutable = True
            self.request.GET.update({"otp": attrs['otp']})
            self.request.GET._mutable = False
        try:
            user, __ = self.auth_class().authenticate(self.request)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                raise AuthenticationFailed()

        except AuthenticationFailed:
            msg = _('Unable to log in with provided credentials.')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class ExpiringAuthToken(ObtainAuthToken):
    """View enabling username/password exchange for expiring token."""

    model = ExpiringToken

    def post(self, request, *args, **kwargs):
        """
        Respond to POSTed username/password with token.
        if `BASIC_AUTH_CLASS` is set in the django project's settings, this auth class's authenticate
        function will be called to verify the credentials (this is specific code for Grape and assumes the OTP
        for 2fa will be transported in the request.GET
        """
        try:
            # we load the basic authentication class defined in the django
            # settings this class has to implement the `authenticate` function
            get_class = lambda name: reduce(
                getattr, name.split('.')[1:], __import__(name.partition('.')[0])
            )
            klass = get_class(settings.BASIC_AUTH_CLASS)
            serializer = AuthTokenOTPSerializer(
                data=request.data, auth_class=klass, request=request
            )

        except AttributeError:
            # if BASIC_AUTH_CLASS is not defined in settings, we use the
            # seializer and is_valid
            serializer = AuthTokenSerializer(data=request.data)

        if serializer.is_valid():
            token, _ = self.model.objects.get_or_create(
                user=serializer.validated_data['user']
            )

            if token.expired():
                # If the token is expired, generate a new one.
                token.delete()
                token = ExpiringToken.objects.create(
                    user=serializer.validated_data['user']
                )

            data = {'token': token.key}
            return Response(data)

        # credentials were not valid
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

    def delete(self, request):
        serializer = AuthTokenSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

        try:
            token = self.model.objects.get(
                user=serializer.validated_data['user']
            )
            token.delete()
        except ExpiringToken.DoesNotExist:
            raise Http404

        return Response(status=HTTP_204_NO_CONTENT)


auth_token_view = ExpiringAuthToken.as_view()
