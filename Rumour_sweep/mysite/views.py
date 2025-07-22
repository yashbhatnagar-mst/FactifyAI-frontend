from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate,login,logout
from django.shortcuts import render, redirect
from django.core.files.storage import default_storage
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache



import httpx
import random
from django.core.mail import send_mail
from django.conf import settings


def speedmetro(request):
    value = 90  
    return render(request, 'speedometro.html', {'value': value})



def analyze_news(request):
    if request.method == 'POST':
        text = request.POST.get('text')
        url = request.POST.get('url')
        image = request.FILES.get('image')

       
        credibility_score = 65
        key_findings = [
            "The article cites multiple sources, but their reliability varies.",
            "The language used is generally neutral, but some emotionally charged words are present.",
            "Some claims lack sufficient evidence."
        ]

        recommendations = [
            "Cross-reference information with other reputable news sources.",
            "Investigate the sources cited in the article.",
            "Be cautious of emotionally charged language."
        ]

        # Render the result template with context
        return render(request, 'output.html', {
            'text': text,
            'score': credibility_score,
            'findings': key_findings,
            'recommendations': recommendations
        })

    return render(request, 'form.html')




def Home_Page(request):
    return render(request,'base.html')



def signup_page(request):
    if  request.method=='POST':
        uname=request.POST.get('name')
        email=request.POST.get('email')
        passw=request.POST.get('password')

        payload = {
            "username": uname,
            "email": email,
            "password": passw,
        }

        response = httpx.post(f"{settings.FASTAPI_BASE_URL}/auth/register", json=payload)

        try:
            api_response = response.json()
        except ValueError:
            api_response = {"message": "Invalid server response", "status": 500, "success": False}

        if api_response.get("success") and api_response.get("status") == 201:
            messages.success(request, api_response.get("message", "Account created successfully!"))
            return redirect('login')
        else:
            messages.error(request, api_response.get("message", "Registration failed."))
            return redirect('signup')
        
    return render(request,'signup.html')
    




    #     if User.objects.filter(username=email).exists():
    #         return HttpResponse("Email is already registered. Please log in.")
    #     my_user = User.objects.create_user(username=email, email=email, password=passw)
    #     my_user.first_name = uname
    #     my_user.save()

    #     messages.success(request, "Thank you for registering! Your information has been saved.")
    #     return redirect('login')
    # return render(request,'signup.html')





def login_page(request):
    if request.method=='POST':
        email=request.POST.get('email')
        passw=request.POST.get('password')

        payload = {
            "username": email, 
            "password": passw
        }

        response = httpx.post(f"http://localhost:8000/api/auth/login", data=payload)
 
        try:
            api_response = response.json()
        except ValueError:
            api_response = {"message": "Invalid server response", "status": 500, "success": False}

        if response.status_code == 200:
            token = api_response.get("data", {}).get("access_token")
            resp = redirect('output')
            resp.set_cookie("clarifyai_token", token,httponly=True, 
                samesite="Lax",  # Or "None" if using cross-origin with https
                secure=False     # True if using https
            )
            messages.success(request, "Login successful!")
            return resp
        else:
            messages.error(request, api_response.get("message", "Invalid login details"))
            return redirect('login')

    return render(request,'login.html')

        


    #     print("login Data:")
    #     print(f"Email: {email}")
    #     print(f"Password: {passw}")

    #     user=authenticate(request,username=email,password=passw)
    #     if user is not None:
    #         login(request,user)
    #         messages.success(request, "Successfully logged in!")
    #         return redirect('output')
    #     else:
    #          messages.error(request, "Invalid details.")
    #          return redirect('login')
    # return render(request,'login.html')


@never_cache
def logoutPage(request):
    if request.user.is_authenticated:
        logout(request)
        request.session.flush()
        messages.success(request, "You have been logged out.")
    return redirect('login')


@login_required(login_url='login')
@never_cache
def output_page(request):
    result=74
    return render(request,'output.html',{'result':result})



def forgot_page(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        if User.objects.filter(email=email).exists():
            otp = str(random.randint(100000, 999999))
            request.session['reset_email'] = email
            request.session['otp'] = otp

            send_mail(
              'Your OTP for Password Reset',
               f'Your OTP is {otp}',
               settings.EMAIL_HOST_USER,  
                fail_silently=False,)

            # Send email (use real email settings in production)
               
            messages.success(request, "OTP sent to your email.")
            return redirect('verification')
        else:
            messages.error(request, "This email is not registered.")

  

# def send_otp_to_email(email, otp):
#     subject = 'Your OTP for Password Reset'
#     message = f'Your OTP is {otp}'
#     from_email = settings.EMAIL_HOST_USER
#     recipient_list = [email]

#     send_mail(subject, message, from_email, recipient_list, fail_silently=False)









def verfication_page(request):
    return render(request,'verfication.html')


def new_password_page(request):
    if request.method == 'POST':
        password1 = request.POST['new_password1']
        password2 = request.POST['new_password2']

        if password1 != password2:
            messages.error(request, "Passwords do not match.")
        else:
            user = request.user  # Or get by token/email in reset flow
            user.set_password(password1)
            user.save()
            messages.success(request, "Password reset successfully.")
            return redirect('login')

    return render(request, 'new_pass.html')



def change_password_page(request):
    return render(request,'change.html')

@login_required(login_url='login')
@never_cache
def profile_page(request):
    return render(request,'profile.html')


def contact_page(request):
    return render(request,'contact.html')

def about_page(request):
    return render(request,'about.html')

def learn_page(request):
    return render(request,'learn.html')


# def create_password_view(request):
#     return render(request,'new_pass.html')

# def settings_page(request):
#     return render(request,'settings.html')



@login_required(login_url='login')
@never_cache
def settings_page(request):
    if request.method == 'POST':
        language = request.POST.get('language')
        privacy = request.POST.get('privacy') == 'on'  # checkbox

        # For demonstration purposes, store in session
        request.session['language'] = language
        request.session['privacy_mode'] = privacy

        messages.success(request, 'Settings updated successfully.')
        return redirect('settings')

    return render(request, 'settings.html', {
        'language': request.session.get('language', 'en'),
        'privacy_mode': request.session.get('privacy_mode', False),
    })
    return render(request, 'settings.html')


@login_required(login_url='login')
@never_cache
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        logout(request)
        user.delete()
        return redirect('base')  # or homepage
    return redirect('settings')


@method_decorator(login_required, name='dispatch')
@never_cache
class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'changepass.html'
    success_url = reverse_lazy('login')




def contact_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')

        # Simple form validation
        if not name or not email or not message:
            messages.error(request, "All fields are required.")
            return redirect('contact')  

       
        messages.success(request, "Your message has been received. We'll get back to you soon!")
        return redirect('contact')  # Clear form on reload

    return render(request, 'contact.html')













# Create your views here.
