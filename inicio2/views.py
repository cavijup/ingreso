# inicio2/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.models import User
from .forms import UserRegistrationForm, LoginForm
from .models import VerificationToken
# Importaciones adicionales para views.py
from .forms import PasswordResetRequestForm, PasswordResetForm
from .models import PasswordResetToken

# Función para manejar la redirección desde la raíz
def home_redirect(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    else:
        return redirect('login')
    
def register_view(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False  # Usuario inactivo hasta verificar email
            user.save()
            
            # Crear token de verificación
            token = VerificationToken.objects.create(user=user)
            
            # Enviar correo de verificación
            current_site = get_current_site(request)
            mail_subject = 'Activa tu cuenta'
            message = render_to_string('email_verification.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token.token,
            })
            send_mail(
                mail_subject,
                message,
                'noreply@yourapp.com',
                [user.email],
                html_message=message,
                fail_silently=False,
            )
            
            messages.success(request, 'Cuenta creada correctamente. Por favor, verifica tu correo electrónico para activarla.')
            return redirect('email_verification_sent')
    else:
        form = UserRegistrationForm()
    return render(request, 'register.html', {'form': form})

def email_verification_sent(request):
    """Página que informa al usuario que se ha enviado un correo de verificación."""
    return render(request, 'email_verification_sent.html')

def verify_email(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        token_obj = VerificationToken.objects.get(user=user, token=token)
        
        if token_obj.is_valid() and not token_obj.is_verified:
            user.is_active = True
            user.save()
            token_obj.is_verified = True
            token_obj.save()
            messages.success(request, 'Tu cuenta ha sido activada. Ahora puedes iniciar sesión.')
        else:
            messages.error(request, 'El enlace de activación es inválido o ha expirado.')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, VerificationToken.DoesNotExist):
        messages.error(request, 'El enlace de activación es inválido.')
    
    return redirect('login')

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Tu cuenta no está activada. Por favor, verifica tu correo electrónico.')
            else:
                messages.error(request, 'Nombre de usuario o contraseña incorrectos.')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')  # 'login' es el nombre de tu vista de inicio de sesión

# Añadir al archivo views.py existente
def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            user = User.objects.get(email=email)
            
            # Eliminar tokens existentes si los hay
            PasswordResetToken.objects.filter(user=user).delete()
            
            # Crear nuevo token
            token = PasswordResetToken.objects.create(user=user)
            
            # Enviar correo con enlace para restablecer contraseña
            current_site = get_current_site(request)
            mail_subject = 'Restablece tu contraseña'
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token.token,
            })
            send_mail(
                mail_subject,
                message,
                'noreply@yourapp.com',
                [user.email],
                html_message=message,
                fail_silently=False,
            )
            
            messages.success(request, 'Te hemos enviado un correo con instrucciones para restablecer tu contraseña.')
            return redirect('login')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'password_reset_request.html', {'form': form})

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        token_obj = PasswordResetToken.objects.get(user=user, token=token)
        
        if not token_obj.is_valid():
            messages.error(request, 'El enlace de restablecimiento de contraseña ha expirado.')
            return redirect('password_reset_request')
        
        if request.method == 'POST':
            form = PasswordResetForm(request.POST)
            if form.is_valid():
                user.set_password(form.cleaned_data.get('password1'))
                user.save()
                
                # Eliminar token después de uso
                token_obj.delete()
                
                messages.success(request, 'Tu contraseña ha sido restablecida. Ahora puedes iniciar sesión.')
                return redirect('login')
        else:
            form = PasswordResetForm()
            
        return render(request, 'password_reset_confirm.html', {'form': form})
        
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, PasswordResetToken.DoesNotExist):
        messages.error(request, 'El enlace de restablecimiento de contraseña es inválido.')
        return redirect('password_reset_request')