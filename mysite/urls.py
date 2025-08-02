

from django.contrib import admin
from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views



urlpatterns = [

    path('',views.home_page,name="home"),
    path('about/',views.about_page,name="about"),
    path('analyze/',views.analyze_news,name='analyze'),
    path('update_pass/', views.update_password_page,name='update_pass'),
    path('change_password/',views.new_password_page,name="change_password"),
    path('contact/',views.contact_page,name="contact"),
    path('delete_account/',views.delete_account, name='delete_account'), 
    path('extension/',views.extension_btn, name='extension_btn'), 
    path('signup/',views.signup_page,name="signup"),
    path('success/',views.success_page,name="success"),
    path('login/',views.login_page,name="login"),
    path('logout/',views.logoutPage,name="logout"),
    path('message/',views.message, name='message'),
    path('forgot/',views.forgot_page,name="forgot"),
    path('verification/',views.verification_page,name="verification"),
    path('new_password/',views.new_password_page,name="new_password"),
    path('google/callback/', views.google_login_callback, name='google_callback_direct'),
    path('login/google/',views.google_login_redirect, name='google_login'),
    path('login/callback/', views.google_login_callback, name='google_callback'),
    path('output/',views.output_page,name="output"),
    path('trending/',views.trending, name='trending'),
    path('term/', views.term, name='term'),        
]