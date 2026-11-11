from __future__ import annotations

import hashlib
import os
from typing import List

from django.conf import settings

from .models import DocumentChunk, DocumentUpload


try:
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain_community.vectorstores import FAISS
    from langchain_openai import ChatOpenAI, OpenAIEmbeddings
except Exception:  # pragma: no cover - optional dependency fallback
    RecursiveCharacterTextSplitter = None
    FAISS = None
    ChatOpenAI = None
    OpenAIEmbeddings = None


def _safe_file_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file_obj:
        for chunk in iter(lambda: file_obj.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_pdf_text(file_path: str) -> str:
    try:
        from pypdf import PdfReader
    except Exception:
        return ''

    reader = PdfReader(file_path)
    text_chunks = []
    for page in reader.pages:
        page_text = page.extract_text() or ''
        if page_text:
            text_chunks.append(page_text)
    return '\n'.join(text_chunks)


def get_user_documents(user) -> List[DocumentUpload]:
    return list(DocumentUpload.objects.filter(user=user, is_active=True).order_by('-uploaded_at'))


def split_text_into_chunks(text: str, chunk_size: int = 800, overlap: int = 120) -> List[str]:
    if not text:
        return []
    if RecursiveCharacterTextSplitter is not None:
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=overlap,
            separators=['\n\n', '\n', ' ', '']
        )
        return splitter.split_text(text)
    paragraphs = [part.strip() for part in text.split('\n\n') if part.strip()]
    chunks = []
    current = ''
    for para in paragraphs:
        if len(current) + len(para) < chunk_size:
            current = f'{current}\n{para}'.strip()
        else:
            if current:
                chunks.append(current)
            current = para
    if current:
        chunks.append(current)
    return chunks


def store_document_for_user(user, uploaded_file, title: str):
    document = DocumentUpload.objects.create(
        user=user,
        title=title,
        file=uploaded_file,
    )

    file_path = document.file.path
    if os.path.exists(file_path):
        text = extract_pdf_text(file_path)
        document.extracted_text = text[:50000]
        document.save(update_fields=['extracted_text'])

        chunks = split_text_into_chunks(text)
        if chunks:
            DocumentChunk.objects.filter(document=document).delete()
            for index, chunk in enumerate(chunks):
                if chunk.strip():
                    DocumentChunk.objects.create(document=document, chunk_index=index, text=chunk)

        document.content_hash = _safe_file_hash(file_path)
        document.save(update_fields=['content_hash'])

    return document


def retrieve_relevant_chunks(user, query: str, k: int = 4):
    chunks = list(DocumentChunk.objects.filter(document__user=user, document__is_active=True).select_related('document'))
    if not chunks:
        return []

    texts = [chunk.text for chunk in chunks]
    if settings.OPENAI_API_KEY and OpenAIEmbeddings is not None and FAISS is not None:
        vectorstore = FAISS.from_texts(texts, OpenAIEmbeddings(openai_api_key=settings.OPENAI_API_KEY))
        matches = vectorstore.similarity_search(query, k=k)
        return [match.page_content for match in matches]

    query_terms = [term.lower() for term in query.split() if len(term) > 2]
    scored = []
    for chunk in chunks:
        text = chunk.text.lower()
        score = sum(1 for term in query_terms if term in text)
        if score:
            scored.append((score, chunk.text))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [chunk_text for _, chunk_text in scored[:k]]


def answer_question_from_documents(user, question: str):
    chunks = retrieve_relevant_chunks(user, question)
    if not chunks:
        return {
            'answer': 'Please upload a PDF first so the assistant can answer using your documents.',
            'sources': [],
        }

    context = '\n\n'.join(chunks)
    if settings.OPENAI_API_KEY and ChatOpenAI is not None:
        llm = ChatOpenAI(model='gpt-4o-mini', temperature=0.2, openai_api_key=settings.OPENAI_API_KEY)
        prompt = (
            'Answer only using the provided context. If the answer is not in the context, say that it is not available in the uploaded documents.\n\n'
            f'Context:\n{context}\n\nQuestion:\n{question}'
        )
        response = llm.invoke(prompt)
        answer = response.content if hasattr(response, 'content') else str(response)
    else:
        answer = (
            'This environment is running without an OpenAI API key, so the assistant is returning a grounded summary from the uploaded document snippets.\n\n'
            f'{context[:2000]}'
        )

    return {
        'answer': answer,
        'sources': chunks,
    }
