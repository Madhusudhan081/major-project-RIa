from django.urls import path
from riaapp import views

urlpatterns = [
   path('',views.index,name="index"),
   path('signin',views.handleSignin,name="handleSignin"), 
   path('login',views.handleLogin,name="handleLogin"), 
   path('logout',views.handleLogout,name="handleLogout"), 
   path('enroll',views.enroll,name="enroll"),
   path('about',views.about,name="about"),
   path('courses',views.courses,name="courses"),
   path('attendance',views.attendance,name="attendance"),
   path('candidateprofile',views.profile,name="profile"),
   path('candidateupdate/<id>',views.candidateupdate,name="candidateupdate"),
   
   path('course/<id>',views.course,name="course"),
   path('contact',views.contact,name="contact"),
   path('activate/<uidb64>/<token>',views.ActivateAccountView.as_view(),name='activate'),
   path('request-reset-email/',views.RequestResetEmailView.as_view(),name='request-reset-email'),
   path('set-new-password/<uidb64>/<token>',views.SetNewPasswordView.as_view(),name='set-new-password'),
]
