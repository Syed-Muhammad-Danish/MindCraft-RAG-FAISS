from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .forms import SignUpForm, LoginForm, OTPForm
from .models import CustomUser, OTP, UserKey
import random
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.db import OperationalError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, action):
    subject = f'Your OTP for {action}'
    message = f'Your OTP is {otp}. It is valid for 5 minutes.'
    from_email = settings.DEFAULT_FROM_EMAIL
    send_mail(subject, message, from_email, [email])

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        try:
            if form.is_valid():
                # Store signup data in session but do NOT create the user yet
                request.session['signup_data'] = form.cleaned_data
                email = form.cleaned_data['username']
                # Check if user already exists
                if CustomUser.objects.filter(username=email).exists():
                    messages.error(request, "Email already exists.")
                    return render(request, 'accounts/signup.html', {'form': form})
                # Generate and send OTP
                otp_code = generate_otp()
                otp = OTP(email=email, otp=otp_code, action='signup')
                otp.save()  # Ensure OTP is saved
                send_otp_email(email, otp_code, 'Signup')
                messages.success(request, 'OTP sent to your email.')
                return redirect('otp_verify', action='signup')
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        messages.error(request, f"{field}: {error}")
        except OperationalError as e:
            messages.error(request, 'Database error: Please ensure migrations are applied.')
    else:
        form = SignUpForm()
        # Check if the table exists before rendering the form
        try:
            CustomUser.objects.exists()
        except OperationalError:
            messages.error(request, 'Database error: Please ensure migrations are applied.')
    return render(request, 'accounts/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            cnic = form.cleaned_data['cnic']

            # Authenticate user
            user = authenticate(request, username=username, password=password)
            if user is not None:
                try:
                    decrypted_cnic = user.decrypt_cnic()
                    print(f"Login - Provided CNIC: {cnic}, Decrypted CNIC: {decrypted_cnic}")
                    if decrypted_cnic == cnic:
                        # Store credentials in session for OTP verification
                        request.session['login_data'] = {
                            'username': username,
                            'password': password,
                            'cnic': cnic
                        }
                        # Generate and send OTP
                        otp_code = generate_otp()
                        otp = OTP(email=username, otp=otp_code, action='login')
                        otp.save()  # Ensure OTP is saved
                        send_otp_email(username, otp_code, 'Login')
                        messages.success(request, 'OTP sent to your email.')
                        return redirect('otp_verify', action='login')
                    else:
                        messages.error(request, 'Invalid CNIC.')
                except Exception as e:
                    messages.error(request, f'Error decrypting CNIC: {str(e)}')
            else:
                messages.error(request, 'Invalid email or password.')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = LoginForm()
    return render(request, 'accounts/login.html', {'form': form})

def otp_verify(request, action):
    otp = None  # Initialize otp to None
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data['otp']
            email = (request.session.get('signup_data', {}).get('username') if action == 'signup'
                     else request.session.get('login_data', {}).get('username'))

            if not email:
                messages.error(request, "Session expired. Please try again.")
                return redirect('signup' if action == 'signup' else 'login')

            try:
                # Retrieve the OTP object from the database
                otp = OTP.objects.get(email=email, otp=otp_code, action=action)
            except OTP.DoesNotExist:
                messages.error(request, 'Invalid OTP.')
                return render(request, 'accounts/otp_verify.html', {'form': form, 'action': action})

            # Check if OTP is expired or max attempts reached
            if otp.is_expired():
                otp.delete()
                messages.error(request, 'OTP has expired.')
                if action == 'signup' and 'signup_data' in request.session:
                    del request.session['signup_data']
                elif action == 'login' and 'login_data' in request.session:
                    del request.session['login_data']
                return redirect('signup' if action == 'signup' else 'login')

            if not otp.can_attempt():
                otp.delete()
                messages.error(request, 'Maximum OTP attempts reached.')
                if action == 'signup' and 'signup_data' in request.session:
                    del request.session['signup_data']
                elif action == 'login' and 'login_data' in request.session:
                    del request.session['login_data']
                return redirect('signup' if action == 'signup' else 'login')

            # Increment attempts
            otp.attempts += 1
            otp.save()

            # Verify OTP
            otp.is_verified = True
            otp.save()

            if action == 'signup':
                signup_data = request.session.get('signup_data')
                try:
                    # Create user only after OTP verification, explicitly set is_active=True
                    user = CustomUser.objects.create_user(
                        username=signup_data['username'],
                        password=signup_data['password1'],
                        first_name=signup_data['first_name'],
                        last_name=signup_data['last_name'],
                        unique_11_digit_number=signup_data['unique_11_digit_number'],
                        cnic=signup_data['cnic'],
                        is_active=True  # Explicitly set is_active to True
                    )
                    # Debug: Check is_active immediately after creation
                    print(f"User {user.username} created with is_active={user.is_active}")
                    # Generate RSA keys
                    private_key = rsa.generate_private_key(
                        public_exponent=65537,
                        key_size=2048
                    )
                    public_key = private_key.public_key()
                    # Extract RSA key components
                    private_numbers = private_key.private_numbers()
                    public_numbers = public_key.public_numbers()
                    # Create a UserKey for the user
                    UserKey.objects.create(
                        user=user,
                        public_key_e=str(public_numbers.e),
                        public_key_n=str(public_numbers.n),
                        private_key_d=str(private_numbers.d),
                        private_key_n=str(private_numbers.public_numbers.n)
                    )
                    print(f"UserKey created for user: {user.username} with e={public_numbers.e}, n={public_numbers.n}")
                    # Attempt to log the user in
                    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                    # Debug: Check if user is authenticated
                    print(f"User {user.username} authenticated: {request.user.is_authenticated}")
                    if not request.user.is_authenticated:
                        messages.error(request, 'Failed to authenticate user after signup.')
                        return redirect('login')
                    messages.success(request, 'Account created successfully!')
                    if 'signup_data' in request.session:
                        del request.session['signup_data']
                    # Redirect using the user's username
                    print(f"Redirecting to chat_room for user: {user.username}")
                    return redirect('chat_room', username=user.username)
                except Exception as e:
                    messages.error(request, f'Error creating user: {str(e)}')
                    if 'signup_data' in request.session:
                        del request.session['signup_data']
                    return redirect('signup')

            elif action == 'login':
                login_data = request.session.get('login_data')
                username = login_data['username']
                password = login_data['password']
                cnic = login_data['cnic']
                user = authenticate(request, username=username, password=password)
                if user:
                    try:
                        decrypted_cnic = user.decrypt_cnic()
                        print(f"OTP Verify - Provided CNIC: {cnic}, Decrypted CNIC: {decrypted_cnic}")
                        if decrypted_cnic == cnic:
                            # Ensure user is active before login
                            user.is_active = True
                            user.save()
                            print(f"User {user.username} updated with is_active={user.is_active}")
                            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                            print(f"User {user.username} authenticated: {request.user.is_authenticated}")
                            if not request.user.is_authenticated:
                                messages.error(request, 'Failed to authenticate user after login.')
                                return redirect('login')
                            messages.success(request, 'Logged in successfully!')
                            if 'login_data' in request.session:
                                del request.session['login_data']
                            # Redirect using the user's username
                            print(f"Redirecting to chat_room for user: {user.username}")
                            return redirect('chat_room', username=user.username)
                        else:
                            messages.error(request, 'Invalid CNIC.')
                    except Exception as e:
                        messages.error(request, f'Error decrypting CNIC: {str(e)}')
                else:
                    messages.error(request, 'Authentication failed.')
                if 'login_data' in request.session:
                    del request.session['login_data']
                return redirect('login')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            return render(request, 'accounts/otp_verify.html', {'form': form, 'action': action})
    else:
        form = OTPForm()

    # Delete OTP only if it exists and was verified
    if otp and otp.is_verified:
        otp.delete()

    return render(request, 'accounts/otp_verify.html', {'form': form, 'action': action})

def logout_view(request):
    logout(request)
    return redirect('login')