from django.db import models

class Rol(models.Model):
    name = models.CharField(max_length=20, unique=True)
    
    class Meta:
        db_table = 'roles'

    def __str__(self):
        return self.name

class Permiso(models.Model):
    name = models.CharField(max_length=20, unique=True)
    descripcionc = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'permisos'
    
    def __str__(self):
        return self.name
    
