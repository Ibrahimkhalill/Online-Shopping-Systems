from django.shortcuts import render,redirect
from django.contrib.auth.forms import UserCreationForm
from .forms import CreateUserForm
from store.models import Customer
from django.contrib.auth.models import User
from django.contrib.auth import login as Login_process ,logout,authenticate,get_user_model
from django.contrib.auth import login, authenticate  
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes, force_text  
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string  
from .tokens import account_activation_token  
from django.core.mail import EmailMessage  

from django.contrib import messages
# Create your views here.

def register(request):
    if request.user.is_authenticated:
        return redirect('store')
    else:
        form=CreateUserForm()
        if request.method=='POST':
            form =CreateUserForm(request.POST)
            if form.is_valid():  
            # save form in the memory not in database  
                user = form.save(commit=False)  
                user.is_active = False
                user.save()    
                
                
                # to get the domain of the current site  
                current_site = get_current_site(request)  
                mail_subject = 'Activation link has been sent to your email id'  
                message = render_to_string('user/acc_active_email.html', {  
                    'user': user,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                    'token':account_activation_token.make_token(user),  
                })  
                to_email = form.cleaned_data.get('email')  
                email = EmailMessage(  
                            mail_subject, message, to=[to_email]  
                )  
                if email.send():
                    username = form.cleaned_data.get('username')
                    x=User.objects.filter(username=username)[0]
                    x=Customer(user=x)
                    x.save()
                    messages.success(request, f'Please confirm your email address to complete the registration')
                else:
                   messages.error(request,'Problem sending email to {to_email}, check if you typed it correctly.')
                
            else:
                context={'form':form}
                return render(request,'user/register.html',context)
    context={'form':form}
    return render(request,'user/register.html',context)

def activate(request, uidb64, token):  
    User = get_user_model()  
    try:  
        uid = force_text(urlsafe_base64_decode(uidb64))  
        user = User.objects.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
        user = None  
    if user is not None and account_activation_token.check_token(user, token):  
        user.is_active = True  
        user.save()  
        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return redirect('login')  
    else:  
       messages.error(request, "Activation link is invalid!")
    return redirect('signup') 

def login(request):
    if request.method=='POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            Login_process(request, user)
            return redirect('store')
        else:
             messages.info(request, 'Username OR password is incorrect')

    context={}
    return render(request,'user/login.html',context)
def logoutUser(request):
    logout(request)
    return redirect('store')