from django.urls import path

from . import views

urlpatterns = [
    path('', views.study_dashboard, name='study_home'),
    path('upload/', views.upload_document, name='study_upload_document'),
    path('ask/', views.ask_question, name='study_ask_question'),
]
