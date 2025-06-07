from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import UserSerializer
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.shortcuts import get_object_or_404

from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication


from django.contrib.auth.models import User

@api_view(['POST'])
def login(request):
    print(request.data)
    user = get_object_or_404(User, email=request.data['email'])

    if not user.check_password(request.data['password']):
        return Response({"error":"Invalid password"},status=status.HTTP_400_BAD_REQUEST)

    token, created = Token.objects.get_or_create(user=user)
    serializer = UserSerializer(instance=user)

    return Response({
        "token": token.key,
        "user": serializer.data
    }, status = status.HTTP_200_OK)



@api_view(['POST'])
@authentication_classes([TokenAuthentication]) 
@permission_classes([AllowAny])
def register(request):
    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():
        serializer.save()

        user = User.objects.get(username=serializer.data['username'])
        user.set_password(serializer.data['password'])
        
        if request.data.get('is_admin') == True:
            if request.user.is_authenticated and request.user.is_superuser:
                user.is_staff = True
                user.is_superuser = True
            else:
                return Response(
                    {'error': 'No autorizado para crear administradores.'},
                    status=status.HTTP_403_FORBIDDEN
                )
        
        user.save()

        token = Token.objects.create(user=user)
        return Response({
            'token': token.key,
            'user': serializer.data            
        }, status = status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def profile(request):

    print(request.data)

    return Response("You are login with {}".format(request.user.username),status=status.HTTP_200_OK)