from rest_framework import serializers
from django.contrib.auth.models import User

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
        if username and len(username) < 4 and len(username) > 20:
            raise serializers.ValidationError("Error: El nombre de usuario debe tener entre 4 y 20 caracteres.")
        if email and len(email) < 4 and len(email) > 50:
            raise serializers.ValidationError("Error: El nombre de usuario debe tener entre 4 y 50 caracteres.")
        
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError("Error: El nombre de usuario ya está en uso.")
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Error: El correo electrónico ya está en uso.")
        return data