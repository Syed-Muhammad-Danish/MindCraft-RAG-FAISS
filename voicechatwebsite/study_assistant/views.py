from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from .models import DocumentUpload
from .services import answer_question_from_documents, get_user_documents, store_document_for_user


@login_required
def study_dashboard(request):
    documents = get_user_documents(request.user)
    answer = None
    sources = []
    if request.method == 'POST':
        question = (request.POST.get('question') or '').strip()
        if question:
            result = answer_question_from_documents(request.user, question)
            answer = result['answer']
            sources = result['sources']
    return render(request, 'study_assistant/dashboard.html', {
        'documents': documents,
        'answer': answer,
        'sources': sources,
    })


@login_required
def upload_document(request):
    if request.method != 'POST':
        return redirect('study_home')

    uploaded_file = request.FILES.get('document')
    if not uploaded_file:
        messages.error(request, 'Please select a PDF file to upload.')
        return redirect('study_home')

    if not uploaded_file.name.lower().endswith('.pdf'):
        messages.error(request, 'Only PDF files are allowed for the study assistant.')
        return redirect('study_home')

    title = request.POST.get('title') or uploaded_file.name
    document = store_document_for_user(request.user, uploaded_file, title)
    messages.success(request, f'Uploaded and indexed "{document.title}" for your study assistant.')
    return redirect('study_home')


@login_required
def ask_question(request):
    if request.method != 'POST':
        return redirect('study_home')

    question = (request.POST.get('question') or '').strip()
    if not question:
        messages.error(request, 'Please enter a question.')
        return redirect('study_home')

    result = answer_question_from_documents(request.user, question)
    documents = get_user_documents(request.user)
    return render(request, 'study_assistant/dashboard.html', {
        'documents': documents,
        'answer': result['answer'],
        'sources': result['sources'],
        'question': question,
    })
