

from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [

    path('',views.Home_Page,name="home"),
    path('signup/',views.signup_page,name="signup"),
    path('login/',views.login_page,name="login"),
    path('forgot/',views.forgot_page,name="forgot"),
    path('verification/',views.verfication_page,name="verification"),
    path('new_password/',views.new_password_page,name="new_password"),
    path('change-password/', views.CustomPasswordChangeView.as_view(),name='change'),
     

    # path('change_password/',views.new_password_page,name="change_password"),
    path('output/',views.output_page,name="output"),
    path('profile/',views.profile_page,name="profile"),
    path('about/',views.about_page,name="about"),
    path('learn/',views.learn_page,name="learn"),
    path('contact/',views.contact_page,name="contact"),
    path('settings/',views.settings_page,name="settings"),
    path('delete-account/', views.delete_account, name='delete_account'),

    
    
]