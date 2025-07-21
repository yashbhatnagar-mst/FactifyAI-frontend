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





# def analyze_news(request):
#     if request.method == 'POST':
#         text = request.POST.get('text')
#         url = request.POST.get('url')
#         image = request.FILES.get('image')

       
#         credibility_score = 65
#         key_findings = [
#             "The article cites multiple sources, but their reliability varies.",
#             "The language used is generally neutral, but some emotionally charged words are present.",
#             "Some claims lack sufficient evidence."
#         ]

#         recommendations = [
#             "Cross-reference information with other reputable news sources.",
#             "Investigate the sources cited in the article.",
#             "Be cautious of emotionally charged language."
#         ]

#         # Render the result template with context
#         return render(request, 'output.html', {
#             'text': text,
#             'score': credibility_score,
#             'findings': key_findings,
#             'recommendations': recommendations
#         })

#     return render(request, 'form.html')




def Home_Page(request):
    return render(request,'base.html')


# def signup_page(request):
#     return render(request,'signup.html')


def signup_page(request):
    if request.method=='POST':
        uname=request.POST.get('name')
        email=request.POST.get('email')
        passw=request.POST.get('password')

        print("Signup Data:")
        print(f"Username:{uname}")
        print(f"Email: {email}")
        print(f"Password: {passw}")

        if User.objects.filter(username=email).exists():
            return HttpResponse("Email is already registered. Please log in.")
        my_user = User.objects.create_user(username=email, email=email, password=passw)
        my_user.first_name = uname
        my_user.save()

        messages.success(request, "Thank you for registering! Your information has been saved.")
        return redirect('login')
    return render(request,'signup.html')


# def login_page(request):
#     return render(request,'login.html')


def login_page(request):
    if request.method=='POST':
        email=request.POST.get('email')
        passw=request.POST.get('password')


        print("login Data:")
        print(f"Email: {email}")
        print(f"Password: {passw}")

        user=authenticate(request,username=email,password=passw)
        if user is not None:
            login(request,user)
            messages.success(request, "Successfully logged in!")
            return redirect('output')
        else:
             messages.error(request, "Invalid details.")
             return redirect('login')
    return render(request,'login.html')



def logoutPage(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('login')



@login_required(login_url='login')
def output_page(request):
    return render(request,'output.html')


def forgot_page(request):
    return render(request,'forgot.html')

def verfication_page(request):
    return render(request,'verfication.html')


def new_password_page(request):
    return render(request,'new_pass.html')

def change_password_page(request):
    return render(request,'change.html')

@login_required(login_url='login')
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
def delete_account(request):
    if request.method == 'POST':
        user = request.user
        logout(request)
        user.delete()
        return redirect('base')  # or homepage
    return redirect('settings')


@method_decorator(login_required, name='dispatch')
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
