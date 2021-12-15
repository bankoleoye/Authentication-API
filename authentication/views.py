from django.shortcuts import render
from rest_framework import generics, status, exceptions, serializers
from .serializers import RegisterSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .otp_generator import generateOTP
import jwt
from django.conf import settings
from rest_framework.views import APIView
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
            return Response({'email':'successfuly activated'}, status=status.HTTP_200_OK)
    
        except jwt.ExpiredSignatureError:
            return Response({'error':'Activation Expired expired'}, status=status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError:
            return Response({'error':'invalid token'}, status=status.HTTP_400_BAD_REQUEST)


# class LoginAPIView(generics.GenericAPIView):
#     serializer_class = LoginSerializer
#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)    
#         return Response(serializer.data, status=status.HTTP_200_OK)        


class Logout(APIView):
    def get(self, request, format=None):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)
    
