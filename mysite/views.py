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
from django.contrib.auth import logout
import random
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.cache import never_cache
from django.http import HttpResponseRedirect
from functools import wraps
import requests # type: ignore


def cookie_required(cookie_name='access_token', redirect_url='login'):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            token = request.COOKIES.get(cookie_name)
            if token:
                return view_func(request, *args, **kwargs)
            return HttpResponseRedirect(redirect_url)
        return _wrapped_view
    return decorator



def google_login_redirect(request):
    return redirect(f'{settings.BACKEND_API_URL}/auth/google/login')


def google_login_callback(request):
    token = request.GET.get('token')
    user_id = request.GET.get('user_id')

    if token and user_id:
        request.session['token'] = token
        request.session['user_id'] = user_id
        messages.success(request, "Google login successful!")
        return redirect('output')
    else:
        messages.error(request, "Google login failed: Missing credentials.")
        return redirect('login')


def home_page(request):
    return render(request,'base.html')


def auth_token_context(request):
    token = request.COOKIES.get('clarifyai_token')
    return {
        'user_authenticated': token is not None
    }



def analyze_news(request):
    if request.method == 'POST':
        text = request.POST.get('text')
        url = request.POST.get('url')
        image = request.FILES.get('image')  
        audio = request.FILES.get('audio')
        api_url = 'https://divyanshi09-factify-ai-backend.hf.space/api/auth/analyze'  
        files = {}
        data = {}

        if text:
            data['text'] = text
        if url:
            data['url'] = url
        if image:
            files['image'] = (image.name, image.read(), image.content_type)
        if audio:
            files['audio'] = (audio.name, audio.read(), audio.content_type)
        

        try:
            response = requests.post(api_url, data=data, files=files)
            print(response)
            if response.status_code == 200:
                result = response.json()

                # Example: extract needed values from API response
                score = result.get('overall_weighted_score', 0)
                findings = [
                    f"Sentiment: {result.get('sentiment')}",
                    f"Authenticity: {result.get('authenticity')}",
                    f"Bias Score: {result.get('bias_score')}",
                ]
                recommendations = ["Consider cross-checking the information."]

                return render(request, 'output.html', {
                    'text': text,
                    'score': round(score, 2),
                    'findings': findings,
                    'recommendations': recommendations
                })

            else:
                return render(request, 'output.html', {
                    'text': text,
                    'score': 0,
                    'findings': ["Failed to get valid response from server."],
                    'recommendations': []
                })

        except Exception as e:
            print(f"Error: {e}")
            return render(request, 'output.html', {
                'text': text,
                'score': 0,
                'findings': ["Error connecting to analysis server."],
                'recommendations': []
            })

    return render(request, 'output.html')


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

        response = requests.post(f"{settings.BACKEND_API_URL}/auth/register", json=payload)

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
    

def login_page(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        passw = request.POST.get('password')

        payload = {
            "username": email,
            "password": passw
        }

        # Make request to backend API
        response = requests.post(f"{settings.BACKEND_API_URL}/auth/login", data=payload)

        # Parse response safely
        try:
            api_response = response.json()
        except ValueError:
            api_response = {"message": "Invalid server response", "status": 500, "success": False}

        # Login success
        if response.status_code == 200:
            token = api_response.get("data", {}).get("access_token")

            resp = redirect('output')

            #  Set cookie without HttpOnly so frontend JS can access it
            resp.set_cookie(
                key="clarifyai_token",
                value=token,
                httponly=False,     #  JS can now read it
                samesite="Lax",
                secure=False        #  Only use True if running on HTTPS
            )

            messages.success(request, "Login successful!")
            return resp

        # Login failed
        else:
            messages.error(request, api_response.get("message", "Invalid login details"))
            return redirect('login')

    return render(request, 'login.html')


@cookie_required(cookie_name='clarifyai_token', redirect_url='/login')
@never_cache
def navbar(request):
    
    token2 = request.COOKIES.get('clarifyai_token')
    print("Token from cookie nav :", token2)  
    is_logged_in = bool(token2)  # Convert to True/False
    return render(request, 'base.html', {
        'is_logged_in': is_logged_in
    })



def logoutPage(request):
    logout(request)
    request.session.flush()

    response = redirect("login")

    # Forcefully delete cookie by matching path
    response.delete_cookie("clarifyai_token", path="/")

    # Optional: also clear sessionid and csrftoken if you want full wipe
    response.delete_cookie("sessionid", path="/")
    response.delete_cookie("csrftoken", path="/")

    messages.success(request, "You have been logged out.")
    return response


# @cookie_required(cookie_name='clarifyai_token', redirect_url='/login')
@never_cache
def output_page(request):
    result=74
    
    return render(request,'output.html',{'result':result})


def forgot_page(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            resp = requests.post(
                f"{settings.BACKEND_API_URL}/auth/forget-password",
                json={"email": email}
            )
            print(resp.status_code, resp.text, "raw response")

            # Try parsing JSON safely
            try:
                data = resp.json()
            except ValueError:
                messages.error(request, "Invalid response from server.")
                return redirect('forgot')

            if data.get('status') == 200:
                messages.success(request, data.get("message", "Email sent!"))
                request.session['otp_email'] = email
                return redirect('verification')
            else:
                messages.error(request, data.get("detail", "Failed to send OTP."))
        except requests.RequestException as e:
            print("Request error:", e)
            messages.error(request, "Error contacting backend service.")
        
        return redirect('forgot')

    return render(request, 'forgot.html')



def verification_page(request):
    if request.method == 'POST':
        otp = request.POST.get('otp')

        # otp_email_cookie =request.COOKIES.get('otp_email')
        email = request.session.get('otp_email')
        # cookies ={'otp_email': otp_email_cookie} if otp_email_cookie else {}
       

        resp = requests.post(
            f"{settings.BACKEND_API_URL}/auth/verify-otp/",
            json={"otp": otp,"email":email},
            # cookies=email  # ← Cookie passed to FastAPI here
        )

        try:
            data = resp.json()
            print(data)  #function call
        except ValueError:
            messages.error(request, "Invalid response from server.")
            return redirect('verification')
        
        
        if not isinstance(data, dict):
            print("Expected dict, got:", type(data), "| Response:", data)
            messages.error(request, "Unexpected response format from backend.")
            return redirect('verification')

        if data.get('status') == 200 and data.get("success"):
            return redirect('change_pass')
        else:
            messages.error(request, data.get("errors", "OTP verification failed."))
            return redirect('verification')

    return render(request, 'verification.html', {
        "email": request.GET.get('email', '')
    })



def new_password_page(request):
    if request.method == "POST":
        pwd1 = request.POST.get("new_password1")
        pwd2 = request.POST.get("new_password2")

        if pwd1 != pwd2:
            messages.error(request, "Passwords do not match.")
            return render(request, "new_pass.html")

        payload = {
            "password": pwd1,
            # Agar aap FastAPI me token/uid pass kar rahe hain:
            "token": request.GET.get("token") or request.session.get("reset_token")
        }

        try:
            resp = request.post(
                f"{settings.BACKEND_API_URL}/auth/update-password/",
                json=payload,
                timeout=5
            )
            data = resp.json()
        except Exception:
            messages.error(request, "Server error. Please try again later.")
            return render(request, "new_pass.html")

        if resp['status'] == 200 and data.get("success"):
            messages.success(request, data.get("message", "Password reset successful!"))
            return redirect("login")
        else:
            messages.error(request, data.get("message", "Failed to reset password."))
            return render(request, "new_pass.html")

    return render(request, "new_pass.html")





def change_password_page(request):
    # GET request pe form render karein
    if request.method == "GET":
        return render(request, "changepass.html")

    # POST request pe process karein
    if request.method == "POST":
        old = request.POST.get("old_password")
        new = request.POST.get("new_password")
        # validation
        if not old or not new:
            messages.error(request, "Fields cannot be empty.")
            return render(request, "changepass.html")

        # FastAPI endpoint ko call karein
        resp = requests.post(
            f"{settings.BACKEND_API_URL}/auth/reset-password",
            json={
                "old_password": old,
                "new_password": new,
                # agar email/session me hai:
                "email": request.user.email
            }
        )

        try:
            data = resp.json()
        except ValueError:
            data = {}

        # Response handle karein
        if resp['status'] == 200 and data.get("success"):
            messages.success(request, data.get("message", "Password changed successfully."))
            return redirect("login")
        else:
            messages.error(request, data.get("message", "Failed to change password."))
            return render(request, "change_pass.html")





def contact_page(request):
    if request.method == "GET":
        return render(request, "contact.html")

    # POST handle
    name = request.POST.get("name")
    email = request.POST.get("email")
    msg = request.POST.get("message")

    if not (name and email and msg):
        messages.error(request, "All fields are required.")
        return render(request, "contact.html")

    payload = {
        "name": name,
        "email": email,
        "message": msg
    }

    try:
        resp = requests.post(
            f"{settings.BACKEND_API_URL}/misc/contact/",
            json=payload,
            
        )
        data = resp.json()
        print(data)
    except Exception as e:
        messages.error(request, "Server error — try again later.")
        return render(request, "contact.html")

    if data['status'] == 200 and data.get("success"):
        messages.success(request, data.get("message", "Thank you! We received your message."))
        return redirect("contact")
    else:
        messages.error(request, data.get("message", "Could not send message."))
        return render(request, "contact.html")
    


def about_page(request):
    return render(request,'about.html')




def create_password_view(request):
     return render(request,'new_pass.html')





@cookie_required(cookie_name='clarifyai_token', redirect_url='/login')
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


@cookie_required(cookie_name='clarifyai_token', redirect_url='/login')
@never_cache
def delete_account(request):
    if request.method == 'POST' and request.user.is_authenticated:
        try:
            resp = requests.delete(
                f"{settings.BACKEND_API_URL}/auth/delete/",
                cookies=request.COOKIES,
                
            )
            data = resp.json() if resp.ok else {}
        except Exception:
            data = {}

        if resp['status'] == 200 and data.get("success"):
            # Backend deleted — now clean up locally
            user = request.user
            logout(request)
            user.delete()
            messages.success(request, "Your account was deleted successfully.")
            return redirect('base')
        else:
            messages.error(request, data.get("message", "Could not delete account."))
            return redirect('settings')
    return redirect('settings')




@method_decorator(login_required, name='dispatch')
@never_cache
class CustomPasswordChangeView(PasswordChangeView):
    template_name = 'changepass.html'
    success_url = reverse_lazy('login')


def trending(request):
    trending_news = [
        {
            'title': 'AI Shakes the World Economy',
            'description': 'Artificial Intelligence is revolutionizing industries from healthcare to finance...',
            'image_url': 'https://source.unsplash.com/featured/?ai,technology',
            'link': 'https://news.example.com/ai-impact'
        },
        {
            'title': 'Massive Heatwaves Hit Europe',
            'description': 'Europe is facing one of the hottest summers in history with temperatures soaring above 40°C...',
            'image_url': 'https://source.unsplash.com/featured/?heatwave,europe',
            'link': 'https://news.example.com/europe-heat'
        },
        {
            'title': 'Olympics 2025: Records Broken',
            'description': 'Athletes from around the world have set new records in the latest Olympic games...',
            'image_url': 'https://source.unsplash.com/featured/?olympics,sports',
            'link': 'https://news.example.com/olympics'
        },
        {
            'title': 'Global Markets Rally Amid Tech Boom',
            'description': 'Tech stocks lead global market recovery, with NASDAQ hitting an all-time high...',
            'image_url': 'https://source.unsplash.com/featured/?stocks,finance',
            'link': 'https://news.example.com/markets-rally'
        },
        {
            'title': 'Wildfires Threaten Thousands in California',
            'description': 'Dry weather and high winds have escalated wildfires across California...',
            'image_url': 'https://source.unsplash.com/featured/?wildfire,california',
            'link': 'https://news.example.com/california-wildfires'
        },
        {
            'title': 'Breakthrough in Cancer Research Announced',
            'description': 'Scientists unveil a promising new therapy targeting resistant cancer cells...',
            'image_url': 'https://source.unsplash.com/featured/?cancer,research',
            'link': 'https://news.example.com/cancer-breakthrough'
        },
        {
            'title': 'NASA Prepares for Mars Mission',
            'description': 'NASA’s Mars 2030 mission enters final planning stages...',
            'image_url': 'https://source.unsplash.com/featured/?nasa,mars',
            'link': 'https://news.example.com/nasa-mars'
        },
        {
            'title': 'Electric Vehicles Set New Sales Records',
            'description': 'EVs outsell gas-powered cars in several major markets...',
            'image_url': 'https://source.unsplash.com/featured/?electric,vehicles',
            'link': 'https://news.example.com/ev-sales'
        },
        {
            'title': 'Cybersecurity Breach Affects Millions',
            'description': 'A major data breach has compromised the personal data of millions...',
            'image_url': 'https://source.unsplash.com/featured/?cybersecurity,data',
            'link': 'https://news.example.com/data-breach'
        },
        {
            'title': 'Climate Summit Ends with Global Pledge',
            'description': 'World leaders agree on new climate targets to reduce emissions...',
            'image_url': 'https://source.unsplash.com/featured/?climate,summit',
            'link': 'https://news.example.com/climate-pledge'
        },
    ]
    return render(request, 'trending.html', {'trending_news':trending_news})













