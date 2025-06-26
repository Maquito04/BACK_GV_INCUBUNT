from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import UserSerializer
from .serializers import RolSerializer
from .serializers import PermisoSerializer
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.shortcuts import get_object_or_404

from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication  
 


from django.contrib.auth.models import User
from apps.app1.models import Rol
from apps.app1.models import Permiso

@api_view(['POST'])
def login(request):
    try:
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, email=email)

        if not user.check_password(password):
            return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)

        token, created = Token.objects.get_or_create(user=user)
        serializer = UserSerializer(instance=user)

        return Response({
            "token": token.key,
            "user": serializer.data
        }, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



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

# CREAR Y LISTAR USUARIOS
# *******************************************************************************************

@api_view(['GET','POST'])
@authentication_classes([TokenAuthentication]) 
@permission_classes([IsAuthenticated])      
def users(request):
    if request.method == 'GET':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response({"msg":"Se ha listado correctamente","data":serializer.data}, status=status.HTTP_200_OK)

    elif request.method == 'POST':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            
            user = User.objects.get(username=serializer.data['username'])
            user.set_password(serializer.data['password'])
            
            user.save()

            token = Token.objects.create(user=user)
            
            return Response({
                'token': token.key,
                'user': serializer.data            
            }, status = status.HTTP_201_CREATED)
            
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
# OBTENER, EDITAR Y ELIMINAR USUARIOS
# *******************************************************************************************
    
@api_view(['GET', 'PUT', 'DELETE'])
@authentication_classes([TokenAuthentication]) 
@permission_classes([IsAuthenticated])     
def user_detail(request, pk):
    user = get_object_or_404(User, pk=pk)

    if request.method == 'GET':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = UserSerializer(user)
        return Response({"msg":"El usuario se ha obtenido correctamente","data":serializer.data}, status=status.HTTP_200_OK)

    elif request.method == 'PUT':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg":"El usuario se ha actualizado correctamente","data":serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        user.delete()
        return Response({"msg":"El usuario ha sido eliminado"},status=status.HTTP_204_NO_CONTENT)
    

# CREAR Y LISTAR ROLES
# *******************************************************************************************
    
@api_view(['GET','POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def roles(request):
    if request.method == 'GET':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        roles = Rol.objects.all().order_by('id')
        serializer = RolSerializer(roles, many=True)
        return Response({"msg":"Se ha listado correctamente","data":serializer.data}, status=status.HTTP_200_OK)
    elif request.method == 'POST':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = RolSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg":"Rol creado correctamente","data":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# OBTENER, EDITAR Y ELIMINAR ROLES
# ******************************************************************************************* 
    
@api_view(['GET','PUT','DELETE'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def roles_detail(request,pk):
    rol = get_object_or_404(Rol, pk=pk)
    
    if request.method == 'GET':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = RolSerializer(rol)
        return Response({"msg":"Rol obtenido correctamente","data":serializer.data}, status=status.HTTP_200_OK)
    elif request.method == 'PUT':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = RolSerializer(rol, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg":"Rol actualizado correctamente","data":serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif request.method == 'DELETE':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        rol.delete()
        return Response({"msg":"Rol eliminado correctamente"}, status=status.HTTP_204_NO_CONTENT)
    
# CREAR Y LISTAR PERMISOS
# *******************************************************************************************

@api_view(['GET','POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def permisos(request):
    if request.method == 'GET':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        permisos = Permiso.objects.all().order_by('id')
        serializer = PermisoSerializer(permisos, many=True)
        return Response({"msg":"Se ha listado correctamente","data":serializer.data}, status=status.HTTP_200_OK)
    elif request.method == 'POST':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = PermisoSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg":"Permiso creado correctamente","data":serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# OBTENER, EDITAR Y ELIMINAR PERMISOS
# *******************************************************************************************

@api_view(['GET','PUT','DELETE'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def permisos_detail(request, pk):
    permiso = get_object_or_404(Permiso, pk=pk)
    
    if request.method == 'GET':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = PermisoSerializer(permiso)
        return Response({"msg":"Permiso obtenido correctamente","data":serializer.data}, status=status.HTTP_200_OK)
    elif request.method == 'PUT':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = PermisoSerializer(permiso, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg":"Permiso actualizado correctamente","data":serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    elif request.method == 'DELETE':
        if not request.user.is_staff:
            return Response({"error":"No autorizado"}, status=status.HTTP_401_UNAUTHORIZED)
        permiso.delete()
        return Response({"msg":"Permiso eliminado correctamente"}, status=status.HTTP_204_NO_CONTENT)
