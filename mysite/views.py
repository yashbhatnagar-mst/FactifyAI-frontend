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
from django.views.decorators.csrf import ensure_csrf_cookie


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


@cookie_required(cookie_name='clarifyai_token', redirect_url='/login')
def analyze_news(request):
    if request.method == 'POST':
        text = request.POST.get('text')
        url = request.POST.get('url')
        image = request.FILES.get('image')  
        audio = request.FILES.get('audio')
        api_url =  f"{settings.BACKEND_API_URL}/auth/analyze/"
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
        
        token = request.COOKIES.get('clarifyai_token')
        print(token)
        headers = {
            'Authorization': f'Bearer {token}'
        }

        try:
            response = requests.post(api_url, data=data, files=files,headers=headers)
            print(response)
            if response.status_code == 200:
                result = response.json()

                # Example: extract needed values from API response
                score = result.get('overall_weighted_score',0)
                findings = [
                    f"Sentiment: {result.get('sentiment')}",
                    f"Authenticity: {result.get('authenticity')}",
                    f"Bias Score: {result.get('bias_score')}",
                ]

                text = request.POST.get('text')
                recommendations = result.get('url', ["url"])

                print("Text:", text)                
                print("URL:", url)  
                print("Image:", image)
                print("Audio:", audio)
                print("API Response JSON:", result)


                return render(request, 'output.html', {
                    'text': text,
                    'score': round(60, 2),
                    'score': round(score, 2),
                    'findings': findings,
                    'recommendations': recommendations,
                    'result':result
                    
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
    




@login_required
def dashboard(request):
    user = request.user
    email = user.email or ""
    print(user)
    print(email)
    email_first_letter = email[0].upper() if email else ""
    return render(request, "base.html", {
        "email_first_letter": email_first_letter
    })



def login_page(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        payload = {
            "username": email,
            "password": password
        }
        api_url = f"{settings.BACKEND_API_URL}/auth/login"

        try:
            resp = requests.post(api_url, data=payload, timeout=10)
        except Exception as e:
            print("Login request failed:", e)
            messages.error(request, "Unable to reach authentication server.")
            return redirect('login')

        # print(" Status:", resp.status_code)
        # print(" Resp body:", resp.text)

        api_response = {}
        ct = resp.headers.get("content-type", "")
        if ct.startswith("application/json"):
            try:
                api_response = resp.json()
            except ValueError as e:
                print("JSON parse error:", e)

        print(" Parsed JSON:", api_response, type(api_response))

        raw_data = api_response.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        access_token = data.get("access_token")

        print(" Token:", access_token)

        if resp.status_code == 200 and access_token:
            django_resp = redirect('output')
            django_resp.set_cookie(
                "clarifyai_token",
                access_token,
                httponly=False,
                samesite="Lax",
                secure=False
            )
            messages.success(request, "Login successful!")
            return django_resp
        else:
            messages.error(request, api_response.get("message") or "Invalid login")
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


@cookie_required(cookie_name='clarifyai_token', redirect_url='/login')
@ensure_csrf_cookie
@never_cache
def output_page(request):
    
    
    return render(request,'output.html')


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
        email = request.session.get('otp_email')
        
        print("User pressed verify. OTP:", otp, "| Email from session:", email)
       
        
        try:
            resp = requests.post(
                f"{settings.BACKEND_API_URL}/auth/verify-otp/",
                json={"otp": otp},
                cookies={"otp_email": email}
            )
            print("POST to backend:", resp.request.url)
            print("Status code:", resp.status_code)
            print("Response text:", resp.text)
            data = resp.json()

        except ValueError:
            messages.error(request, "Invalid response from server.")
            return redirect('verification')
        
        
        if not isinstance(data, dict):
            print("Expected dict, got:", type(data), "| Response:", data)
            messages.error(request, "Unexpected response format from backend.")
            return redirect('verification')

        if data.get('status') == 200 and data.get("success"):
            return redirect('new_password')
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
        email = request.session.get('otp_email')

        if pwd1 != pwd2:
            messages.error(request, "Passwords do not match.")
            return render(request, "new_pass.html")

        # token = request.GET.get("token") or request.session.get("reset_token")
        if not email:
            messages.error(request, "Missing email.")
            return render(request, "new_pass.html")

        payload = {
            "new_password": pwd1,
            # "token": email
        }
        
        try:
           
            resp = requests.post(
                f"{settings.BACKEND_API_URL}/auth/reset-password/",
                json=payload,
                cookies={"otp_email": email}
            )
            print("POST to backend:", resp.request.url)
            print("Status code:", resp.status_code)
            print("Response text:", resp.text)
            data = resp.json()

        except ValueError:
            messages.error(request, "Invalid JSON response from server.")
            return render(request, "new_pass.html")
        except Exception as e:
            print("Request exception:", e)
            messages.error(request, "Server error. Please try again.")
            return render(request, "new_pass.html")

        if isinstance(data, dict) and resp.status_code == 200 and data.get("success"):
            messages.success(request, data.get("message", "Password reset successful!"))
            return redirect("login")
        else:
            err = data.get("message") or data.get("errors") or "Failed to reset password."
            messages.error(request, err)
            return render(request, "new_pass.html")

    return render(request, "new_pass.html")



def update_password_page(request):
    if request.method == "GET":
        return render(request, "update_pass.html")

    elif request.method == "POST":
        old = request.POST.get("old_password")
        new = request.POST.get("new_password")

        if not old or not new:
            messages.error(request, "Fields cannot be empty.")
            return render(request, "update_pass.html")

        token = request.COOKIES.get('clarifyai_token')
        print("Token:", token)
        print("Old:", old)
        print("New:", new)

        if not token:
            messages.error(request, "You must be logged in.")
            return redirect("login")

        headers = {
            'Authorization': f'Bearer {token}'
        }

        try:
            resp = requests.put(
                f"{settings.BACKEND_API_URL}/auth/update-password",
                json={
                    "old_password": old,
                    "new_password": new
                },
                headers=headers
            )
            data = resp.json()
            print(data)
        except Exception as e:
            print("Request error:", e)
            messages.error(request, "Something went wrong.")
            return render(request, "update_pass.html")

        if resp.status_code == 200 and data.get("success"):
            messages.success(request, data.get("message", "Password changed successfully."))
            return redirect("login")
        else:
            messages.error(request, data.get("message", "Failed to change password."))
            return render(request, "update_pass.html")


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
    print(" DELETE ACCOUNT VIEW HIT")
    if request.method == 'POST' and request.user.is_authenticated:

        # Print karao user aur email/token for debugging
        print("User:", request.user)
        clarify_token = request.COOKIES.get('clarifyai_token')
        print("Token from cookie:", clarify_token)

        if not clarify_token:
            messages.error(request, "Authentication token missing. Please log in again.")
            return redirect('output')

        headers = {
            'Authorization': f'Bearer {clarify_token}',
            'Accept': 'application/json',
        }

        # Final API URL — ensure base + route match backend
        api_url = f"{settings.BACKEND_API_URL}/auth/delete/"
        print("Calling FastAPI DELETE to:", api_url)

        try:
            resp = requests.delete(api_url, headers=headers, timeout=10)
            print("Response status:", resp.status_code)
            print("Response body:", resp.text)
            data = resp.json() if resp.ok else {}
        except Exception as e:
            print("Request to FastAPI failed:", e)
            messages.error(request, "Server error deleting account. Please try later.")
            return redirect('output')

        # Response handling
        if resp.status_code == 200 and data.get("success"):
            # successful deletion in backend
            user = request.user
            logout(request)
            user.delete()
            messages.success(request, "Your account was deleted successfully.")
            return redirect('base')
        else:
            err = data.get("message") or data.get("error") or "Could not delete account."
            messages.error(request, err)
            return redirect('output')

    # agar GET request ho
    return redirect('output')


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













