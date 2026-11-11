from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser
import re
from django.core.validators import RegexValidator
from django.db import OperationalError


class CustomUserCreationForm(UserCreationForm):
    first_name = forms.CharField(max_length=50, required=True)
    last_name = forms.CharField(max_length=50, required=True)
    unique_11_digit_number = forms.CharField(
        max_length=11,
        required=True,
        help_text="Enter exactly 11 digits",
    )
    cnic = forms.CharField(
        max_length=13,
        required=True,
        help_text="Enter exactly 13 digits",
    )

    class Meta:
        model = CustomUser
        fields = (
            'username',
            'first_name',
            'last_name',
            'unique_11_digit_number',
            'cnic',
            'password1',
            'password2',
        )

    def clean_unique_11_digit_number(self):
        number = self.cleaned_data.get('unique_11_digit_number')
        if not re.match(r'^\d{11}$', number):
            raise forms.ValidationError('Must be exactly 11 digits')
        # Check against decrypted values in database
        existing_numbers = [user.decrypt_unique_11_digit_number() for user in CustomUser.objects.all()]
        if number in existing_numbers:
            raise forms.ValidationError('This number is already in use')
        return number

    def clean_cnic(self):
        cnic = self.cleaned_data.get('cnic')
        if not re.match(r'^\d{13}$', cnic):
            raise forms.ValidationError('Must be exactly 13 digits')
        # Check against decrypted values
        existing_cnics = [user.decrypt_cnic() for user in CustomUser.objects.all()]
        if cnic in existing_cnics:
            raise forms.ValidationError('This CNIC is already in use')
        return cnic

class CustomAuthenticationForm(AuthenticationForm):
    cnic = forms.CharField(
        max_length=13,
        required=True,
        help_text="Enter your 13-digit CNIC",
    )

    def clean_cnic(self):
        cnic = self.cleaned_data.get('cnic')
        if not re.match(r'^\d{13}$', cnic):
            raise forms.ValidationError('Must be exactly 13 digits')
        return cnic

class SignUpForm(UserCreationForm):
    username = forms.EmailField(label='Email', max_length=150)
    first_name = forms.CharField(max_length=50)
    last_name = forms.CharField(max_length=50)
    unique_11_digit_number = forms.CharField(
        max_length=11,
        validators=[RegexValidator(r'^\d{11}$', 'Must be exactly 11 digits')]
    )
    cnic = forms.CharField(
        max_length=13,
        validators=[RegexValidator(r'^\d{13}$', 'Must be exactly 13 digits')]
    )

    class Meta:
        model = CustomUser
        fields = ('username', 'first_name', 'last_name', 'unique_11_digit_number', 'cnic', 'password1', 'password2')

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        unique_11_digit_number = cleaned_data.get('unique_11_digit_number')
        cnic = cleaned_data.get('cnic')

        # Check for existing email
        if username and CustomUser.objects.filter(username=username).exists():
            self.add_error('username', 'This email is already registered.')

        # Check for existing unique_11_digit_number
        try:
            existing_numbers = [user.decrypt_unique_11_digit_number() for user in CustomUser.objects.all()]
            if unique_11_digit_number in existing_numbers:
                self.add_error('unique_11_digit_number', 'This unique 11-digit number is already registered.')
        except OperationalError:
            # If the table doesn't exist, skip this validation
            pass
        except Exception as e:
            self.add_error('unique_11_digit_number', f'Error validating unique 11-digit number: {str(e)}')

        # Check for existing CNIC
        try:
            existing_cnics = [user.decrypt_cnic() for user in CustomUser.objects.all()]
            if cnic in existing_cnics:
                self.add_error('cnic', 'This CNIC is already registered.')
        except OperationalError:
            # If the table doesn't exist, skip this validation
            pass
        except Exception as e:
            self.add_error('cnic', f'Error validating CNIC: {str(e)}')

        return cleaned_data

class LoginForm(forms.Form):
    username = forms.EmailField(label='Email', max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)
    cnic = forms.CharField(
        max_length=13,
        validators=[RegexValidator(r'^\d{13}$', 'Must be exactly 13 digits')]
    )

class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, min_length=6, label='OTP')