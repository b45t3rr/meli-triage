from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app
from app import db
from app.models import Document, Comment, User
from flask_login import login_required, current_user
import os
from werkzeug.utils import secure_filename

# Create main blueprint
main = Blueprint('main', __name__)

@main.route('/')
def index():
    # SQL Injection vulnerability in search
    search_query = request.args.get('q', '')
    if search_query:
        # Vulnerable to SQL Injection
        query = f"SELECT * FROM document WHERE title LIKE '%{search_query}%'"
        documents = db.session.execute(query).fetchall()
    else:
        documents = Document.query.all()
    return render_template('index.html', documents=documents)

@main.route('/document/<int:doc_id>')
@login_required
def view_document(doc_id):
    # IDOR vulnerability - no check if user has access to this document
    document = Document.query.get_or_404(doc_id)
    return render_template('document.html', document=document)

@main.route('/document/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    # Path Traversal vulnerability - intentionally vulnerable
    filename = secure_filename(file.filename)  # This would prevent the vulnerability, but we're not using it
    filename = file.filename  # This is the vulnerable line
    upload_dir = os.path.join(current_app.root_path, 'uploads')
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir, exist_ok=True)
    
    file_path = os.path.join(upload_dir, filename)
    file.save(file_path)
    
    new_doc = Document(
        title=request.form.get('title', 'Untitled'),
        content=request.form.get('content', ''),
        file_path=file_path,
        user_id=current_user.id
    )
    db.session.add(new_doc)
    db.session.commit()
    
    return redirect(url_for('main.view_document', doc_id=new_doc.id))

@main.route('/uploads/<path:filename>')
def download_file(filename):
    # Path Traversal vulnerability - no path sanitization
    return send_from_directory(
        os.path.join(current_app.root_path, 'uploads'),
        filename,
        as_attachment=True
    )

@main.route('/comment', methods=['POST'])
@login_required
def add_comment():
    document_id = request.form.get('document_id')
    content = request.form.get('content')
    
    # Stored XSS vulnerability - user input is not sanitized
    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        document_id=document_id
    )
    db.session.add(new_comment)
    db.session.commit()
    
    return redirect(url_for('main.view_document', doc_id=document_id))
