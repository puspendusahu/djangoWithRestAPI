from rest_framework import serializers
from .models import Note

from rest_framework import serializers
from app.models import User

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "confirm_password"]

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError("Password and Confirm_Password doesn't match.")
        return attrs
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
          raise serializers.ValidationError('user with this Email already exists.')
        return value
    
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password'],
        )
        user.is_active = True
        user.save()
        return user
    
    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.save()
        return instance
    

    
class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ['noteId',"title", "content",'createdAt','updatedAt','user']

    def validate(self, data):
        t = data.get('title')
        c = data.get('content')
        if t == "":
            raise serializers.ValidationError('Title can not be empty')
        elif c == "":
            raise serializers.ValidationError('Content can not be empty')
        return data

    def create(self, validated_data):
        return Note.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.content = validated_data.get('content', instance.content)
        instance.user_id = validated_data.get('user_id', instance.user_id)
        instance.save()
        return instance
    
