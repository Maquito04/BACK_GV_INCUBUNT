from django.db import models

class Permiso(models.Model):
    name = models.CharField(max_length=20, unique=True)
    description = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'permisos'
    
    def __str__(self):
        return self.name

class Rol(models.Model):
    name = models.CharField(max_length=20, unique=True)
    permisos = models.ManyToManyField(Permiso,through='Rol_Permiso',related_name='roles')
    
    class Meta:
        db_table = 'roles'

    def __str__(self):
        return self.name
    
class Rol_Permiso(models.Model):
    rol = models.ForeignKey(Rol,on_delete=models.CASCADE)
    permiso = models.ForeignKey(Permiso,on_delete=models.CASCADE)
    
    class Meta:
        db_table = 'rol_permisos'
        unique_together = ('rol','permiso')
        
    def __str__(self):
        return f"{self.rol.name} - {self.permiso.name}"
    
    
