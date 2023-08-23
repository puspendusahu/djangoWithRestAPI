from django.contrib import admin
from django.urls import path
from app import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('app/csrf_cookie/', views.GetCSRFToken.as_view()),
    path('GET/notes/', views.GETNoteAPI.as_view()),
    path('GET/notes/<int:pk>/', views.GETNoteAPI.as_view()),
    path('POST/notes/', views.POSTNoteAPI.as_view()),
    path('PUT/notes/<int:pk>/', views.PUTNoteAPI.as_view()),
    path('DELETE/notes/<int:pk>/', views.DeleteNoteAPI.as_view()),

    path('app/user/', views.UserDetailView.as_view(), name='user_detail'),
    path('app/checkauth/', views.CheckAuthenticatedView.as_view(), name='check_auth'),
    path('app/registration/', views.RegistrationView.as_view(), name='register'),
    path('app/login/', views.LoginView.as_view(), name='login'),
    path('app/change_password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('app/delete/', views.DeleteAccountView.as_view(), name='user_delete'),
    path('app/logout/', views.LogoutView.as_view(), name='logout'),


]