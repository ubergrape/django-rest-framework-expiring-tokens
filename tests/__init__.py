from rest_framework.exceptions import AuthenticationFailed


class TestAuthenticationClass(object):
    def authenticate(self, request):
        from django.contrib.auth.models import User
        user = User.objects.create_user(
            username="franz",
            email="franz@test.com",
            password="password"
        )
        if "otp" in request.GET:
            return user, None

        else:
            raise AuthenticationFailed("OTP missing yo")


