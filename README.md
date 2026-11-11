# MindCraft

MindCraft is a secure AI study assistant designed for document-based learning and research. It allows users to upload PDF files, retrieve relevant context from their own uploaded documents, and ask questions grounded in those documents instead of guessing from general knowledge.

The app is built with Django and keeps document access scoped to the authenticated user, so each user only sees the data they uploaded.

## What this project does

- Secure user authentication with OTP verification
- PDF upload and indexing for personal study materials
- Retrieval-augmented generation (RAG) over the user’s documents only
- Grounded answers with document-based context
- Side feature: chat/real-time messaging remains available

## Core idea

MindCraft is meant to behave like a private academic assistant:

- Users upload their notes, lecture PDFs, and study material
- The system extracts text from those PDFs
- Relevant content is retrieved based on a question
- The answer is generated only from the retrieved document context
- Data separation is enforced so one user cannot access another user’s documents

## Project structure

```text
Code2/
├── requirements.txt
├── README.md
├── .gitignore
├── voicechatwebsite/
│   ├── manage.py
│   ├── db.sqlite3
│   ├── accounts/
│   ├── chat/
│   ├── study_assistant/
│   ├── templates/
│   ├── static/
│   ├── media/
│   └── voicechatwebsite/
└── .venv/                    # optional local environment folder
```

## Features

### Secure study assistant
- PDF upload from the dashboard
- Per-user document ownership
- Retrieval filtered by the active user
- Answers grounded in document excerpts
- Source references from uploaded material

### Authentication
- User signup and login
- OTP verification flow
- Console email backend for local development

### Secondary functionality
- Legacy chat interface remains available as a support feature
- Not the primary product flow

## Tech stack

- Django 5.2
- SQLite for local development
- Django Channels for real-time chat
- OpenAI API for LLM-based answer generation
- LangChain + FAISS for retrieval support
- PyPDF for PDF text extraction

## Prerequisites

Before running the project, make sure you have:

- Python 3.10+
- pip
- virtual environment support

## Local setup

1. Clone the repository

```bash
git clone <your-github-repo-url>
cd Code2
```

2. Create and activate a virtual environment

On Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

On macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

4. Set environment variables

Create a `.env` file in the project root or use your shell environment:

```env
OPENAI_API_KEY=your_openai_key_here
SECRET_KEY=your_django_secret_key
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
```

For production, use a real SMTP backend instead of the console fallback.

5. Run migrations

```bash
cd voicechatwebsite
python manage.py migrate
```

6. Start the app

```bash
python manage.py runserver
```

Then open:

```text
http://127.0.0.1:8000/
```

The app redirects to the study dashboard flow after login.

## Default workflow

1. Sign up for a new account
2. Verify OTP
3. Log in
4. Upload a PDF in the study dashboard
5. Ask a question related to the uploaded document
6. Review the answer and the related document snippets

## Security notes

This project is designed to keep user data isolated:

- document retrieval is filtered by the logged-in user
- documents are not shared across accounts in the core retrieval flow
- AI answers are generated from the user’s uploaded files only

For production deployment, also add:

- strong secret management
- HTTPS enforcement
- password hashing hardening
- real email delivery service
- environment-based configuration for all secrets

## Important reminder

The current project is a secure study assistant and RAG-based learning tool. The old chat feature remains available as a secondary feature, but the main product direction is document-grounded AI study assistance.

## GitHub push

Once the remote is ready, run:

```bash
git init
git add .
git commit -m "Initial commit: MindCraft study assistant"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

## License

This project is intended for educational and project-development use. Add a license file if you plan to publish it publicly.
