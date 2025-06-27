from rest_framework import serializers
from django.contrib.auth.models import User
from apps.app1.models import Rol
from apps.app1.models import Permiso
from apps.app1.models import Rol_Permiso

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username','email','password']
        
    def validate(self, data):
        password = data.get('password')
        username = data.get('username')
        email = data.get('email')
        
        if password and len(password) < 4:
            raise serializers.ValidationError("Error: La contraseña debe tener al menos 4 caracteres.")
        if username and (len(username) < 4 or len(username) > 20):
            raise serializers.ValidationError("Error: El nombre de usuario debe tener entre 4 y 20 caracteres.")
        if email and (len(email) < 4 or len(email) > 50):
            raise serializers.ValidationError("Error: El nombre de usuario debe tener entre 4 y 50 caracteres.")
        
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError("Error: El nombre de usuario ya está en uso.")
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Error: El correo electrónico ya está en uso.")
        return data
    
class RolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rol
        fields = ['id','name']
    
    def validate(self, data):
        name = data.get('name')
        
        if name and (len(name) < 4 or len(name) > 20):
            raise serializers.ValidationError("Error: El nombre del rol debe tener entre 4 y 20 caracteres.")
        
        if Rol.objects.filter(name=name).exists():
            raise serializers.ValidationError("Error: El nombre del rol ya está en uso.")
        return data
    
class PermisoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permiso
        fields = ['id','name','description']
    
    def validate(self, data):
        name = data.get('name')
        description = data.get('description')
        
        if name and (len(name) < 4 or len(name) > 20):
            raise serializers.ValidationError("Error: El nombre del permiso debe tener entre 4 y 20 caracteres.")
        if description and len(description) < 4 and len(description) > 255:
            raise serializers.ValidationError("Error: La descripción del permiso debe tener entre 4 y 255 caracteres.")
        
        if Permiso.objects.filter(name=name).exists():
            raise serializers.ValidationError("Error: El nombre del permiso ya está en uso.")
        return data
    
class RolPermisoSerializaer(serializers.ModelSerializer):
    class Meta:
        model = Rol_Permiso
        fields = ['id','rol','permiso']
        
        