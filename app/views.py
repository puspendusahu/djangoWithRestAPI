from django.shortcuts import render
from rest_framework.response import Response
from .models import Note, User
from .serializers import NoteSerializer, UserSerializer
from rest_framework import status
from rest_framework.views import APIView
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from rest_framework.permissions import AllowAny
from django.utils.decorators import method_decorator
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect



@method_decorator(ensure_csrf_cookie, name="dispatch")
class GetCSRFToken(APIView):
    permission_classes = [AllowAny]
    def get(self, request):
        return Response({"success": "CSRF Cookie Set"})


class GETNoteAPI(APIView):
    permission_classes = [AllowAny]
    def get(self, request, pk=None, format=None):
        id = pk
        user = request.user
        if request.user.is_authenticated:
            if id is not None:
                try:
                    nData = Note.objects.get(noteId=id)
                except Note.DoesNotExist:
                    return Response({"msg": "Data Not available"}, status=status.HTTP_201_CREATED)
                serializer = NoteSerializer(nData)
                return Response(serializer.data)
            noteData = Note.objects.filter(user=user)
            serializer = NoteSerializer(noteData, many=True)
            return Response(serializer.data)
        else:
            return Response({"msg":"Anonymous User"})

 
@method_decorator(csrf_protect, name='dispatch')
class POSTNoteAPI(APIView):
    permission_classes = [AllowAny]
    def post(self, request, format=None):
        if request.user.is_authenticated:
            currentUser = request.user
            userData = User.objects.get(email=currentUser)
            request.data['user'] = userData.pk
            serializer = NoteSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"msg": "Data Created"}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"msg":"Anonymous User"})



@method_decorator(csrf_protect, name='dispatch')
class PUTNoteAPI(APIView):
    permission_classes = [AllowAny]
    def put(self, request, pk, format=None):
        id = pk
        if request.user.is_authenticated:
            currentUser = request.user
            userData = User.objects.get(email=currentUser)
            request.data['user'] = userData.pk
            try:
                note = Note.objects.get(noteId=id)
            except Note.DoesNotExist:
                return Response({"msg": "Data Not available"}, status=status.HTTP_201_CREATED)
            serializer = NoteSerializer(note, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"msg": "Complete Data Updated"})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"msg":"Anonymous User"})
    

@method_decorator(csrf_protect, name='dispatch')
class DeleteNoteAPI(APIView):
    permission_classes = [AllowAny]
    def delete(self, request, pk, format=None):
        id = pk
        if request.user.is_authenticated:
            currentUser = request.user
            userData = User.objects.get(email=currentUser)
            request.data['user'] = userData.pk
            try:
                note = Note.objects.get(pk=id)
            except Note.DoesNotExist:
                return Response({"msg": "Data Not available"}, status=status.HTTP_201_CREATED)
            note.delete()
            return Response({"msg": "Data Deleted"})
        else:
            return Response({"msg":"Anonymous User"})




@method_decorator(csrf_protect, name='dispatch')
class CheckAuthenticatedView(APIView):
    permission_classes=[AllowAny]
    def get(self, request):
        if request.user.is_authenticated:
            return Response({'isAuthenticated': True})
        else:
            return Response({'isAuthenticated': False})
 

@method_decorator(csrf_protect, name='dispatch')
class RegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.create(serializer.validated_data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(request, email=email, password=password)
     
        if user is not None:
            if user.is_active:
                login(request, user)
                return Response({'detail':'Logged in successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Email or Password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        

class ChangePasswordView(APIView):
    def post(self, request):
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        user = request.user

        if not user.check_password(old_password):
            return Response({'detail': 'Invalid old password.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({'detail': 'Password changed successfully.'}, status=status.HTTP_200_OK)
    
class DeleteAccountView(APIView):
    def delete(self, request):
        user = request.user
        user.delete()
        logout(request)
        return Response({'detail': 'Account deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        return Response({'detail': 'Logged out successfully.'}, status=status.HTTP_200_OK)
    
class UserDetailView(APIView):
    def get(self, request):
        serializer = UserSerializer(request.user)
        data = serializer.data
        data['is_staff'] = request.user.is_staff
        data['id'] = request.user.id
        return Response(data)