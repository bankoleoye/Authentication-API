from django.shortcuts import render
from rest_framework import generics, status, permissions
from .serializers import RegisterSerializer, LoginSerializer, ResetPasswordSerializer, ForgetPasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .otp_generator import generateOTP
import jwt
from django.conf import settings
from django.contrib.auth import authenticate, logout
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authtoken.models import Token
# Create your views here.


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email = user_data['email'])

        token = RefreshToken.for_user(user).access_token
        print(token)
        OTP = generateOTP()

        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')

        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body = 'Hi '+user.username+' Use the link below to verify your email \n' + 'OTP supplied' + ' ' + OTP + absurl
        data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Verify your email'}
        Util.send_email(data)
        return Response(user_data, status = status.HTTP_201_CREATED)


class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            print('user', user)
            if not user.is_verified:
                user.is_verified = True
                user.is_active = True
                user.save()
            return Response({'email':'successfuly activated'}, status = status.HTTP_200_OK)
    
        except jwt.ExpiredSignatureError:
            return Response({'error':'Activation Expired expired'}, status = status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token'}, status = status.HTTP_400_BAD_REQUEST)


class Login(generics.GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer
    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        if email is None or password is None:
            return Response(errors={'invalid_credentials': 'please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=email, password=password)
        if not user:
            return Response(errors={'invalid_credentials': 'Ensure both email and password are correct and you have verified your account'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response(errors={'invalid_credentials': 'Please verify your account'}, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(user)
        token, _= Token.objects.get_or_create(user=user)
        return Response(data={'token': token.key}, status = status.HTTP_200_OK)
            
    
class Logout(generics.GenericAPIView):
    def get(self, request):
        logout(request)
        return Response(status=status.HTTP_200_OK)

class ForgotPassword(generics.GenericAPIView):
    serializer_class = ForgetPasswordSerializer

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({"message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        OTP = Util.generate_otp(6)
        user.otp = OTP
        email = user.email
        user.save()
        if user.is_active:
            email_body = 'Hi '+user.username+' Here is your Otp code to reset your password \n ' + str(OTP)
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'verify your email'}
            Util.send_email(data)
            return Response({
                "message": "success",
                "errors": None
            }, status=200)


class PasswordReset(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def put(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        otp = serializer.data.get('otp')
        password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')
        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({"message":"User does not exist"}, status=404)
        if password == confirm_password:
            keygen = user.otp
            OTP = keygen
            if otp != OTP:
                return Response({
                "message": "Failure",
                "data": None,
                "errors": {
                    'otp_code': "Does not match or expired",
                }
            }, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(password)
            user.save()
            return Response({
                "message": "success",
                "data": {
                    "otp": None
                },
                "errors": None
            }, status=status.HTTP_200_OK)
        else:
            return Response({"message":"Failure", "data": None,"errors":{
                "passwords": "The two Passwords must be the same"
            }},status=status.HTTP_400_BAD_REQUEST)