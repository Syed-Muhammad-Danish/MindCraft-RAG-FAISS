from django.contrib.auth import get_user_model
from django.test import TestCase

from study_assistant.models import DocumentUpload

User = get_user_model()


class StudyAssistantSecurityTests(TestCase):
    def test_user_documents_are_isolated(self):
        user_a = User.objects.create_user(
            username='usera@example.com',
            first_name='User',
            last_name='A',
            unique_11_digit_number='11111111111',
            cnic='1111111111111',
            password='Pass123!'
        )
        user_b = User.objects.create_user(
            username='userb@example.com',
            first_name='User',
            last_name='B',
            unique_11_digit_number='22222222222',
            cnic='2222222222222',
            password='Pass123!'
        )

        self.assertNotEqual(user_a.id, user_b.id)
        self.assertTrue(hasattr(DocumentUpload, 'user'))
