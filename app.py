from flask import Flask, request, jsonify, session, send_from_directory
import os
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from datetime import datetime, timedelta
import bcrypt
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
import logging
import functools
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database and session configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'xYz9wV1uT0sR9qP8oN7mL6kJ5iH4gF3eD2cB1a'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

db = SQLAlchemy()
db.init_app(app)
Session(app)

@app.before_request
def log_request():
    logger.debug(f"Incoming request: {request.method} {request.path} {request.get_json(silent=True)}")

# Models
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Book(db.Model):
    book_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    isbn = db.Column(db.String(13), unique=True, nullable=False)
    category = db.Column(db.String(50))
    total_copies = db.Column(db.Integer, nullable=False)
    available_copies = db.Column(db.Integer, nullable=False)
    published_year = db.Column(db.Integer)

class Transaction(db.Model):
    transaction_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable=False)
    issue_date = db.Column(db.Date, default=datetime.utcnow().date)
    due_date = db.Column(db.Date, nullable=False)
    return_date = db.Column(db.Date)
    fine_amount = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='borrowed')  # borrowed, overdue, pending_approval, returned
    user = db.relationship('User', backref='transactions')
    book = db.relationship('Book', backref='transactions')

class Reservation(db.Model):
    reservation_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable=False)
    reservation_date = db.Column(db.Date, default=datetime.utcnow().date)
    status = db.Column(db.String(20), default='active')  # active, cancelled
    user = db.relationship('User', backref='reservations')
    book = db.relationship('Book', backref='reservations')

# Authentication decorator
def login_required(role=None):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                logger.error("Unauthorized access: No user session")
                return jsonify({'error': 'Unauthorized access'}), 401
            user = User.query.get(session['user_id'])
            if not user:
                logger.error("Unauthorized access: Invalid user")
                return jsonify({'error': 'Unauthorized access'}), 401
            if role and user.role != role:
                logger.error(f"Access denied: Required role {role}, got {user.role}")
                return jsonify({'error': f'{role.capitalize()} access required'}), 403
            return f(*args, **kwargs)
        return wrapped
    return decorator

# Fine calculation scheduler
def calculate_fines():
    with app.app_context():
        transactions = Transaction.query.filter(
            Transaction.return_date.is_(None),
            Transaction.due_date < datetime.utcnow(),
            Transaction.status != 'pending_approval'
        ).all()
        for t in transactions:
            days_overdue = (datetime.utcnow().date() - t.due_date).days
            t.fine_amount = days_overdue * 1.0
            t.status = 'overdue' if days_overdue > 0 else t.status
            db.session.commit()
        logger.debug(f"Fine calculation completed: {len(transactions)} transactions updated")

scheduler = BackgroundScheduler()
scheduler.add_job(calculate_fines, 'interval', days=1)
scheduler.start()

# Routes
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path != "" and os.path.exists(os.path.join('frontend/build', path)):
        return send_from_directory('frontend/build', path)
    return send_from_directory('frontend/build', 'index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    logger.debug(f"Register data: {data}")
    if not all(key in data for key in ['name', 'email', 'password', 'role']):
        return jsonify({'error': 'Missing required fields'}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    try:
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
        new_user = User(
            name=data['name'],
            email=data['email'],
            password=hashed_password.decode('utf-8'),
            role=data['role']
        )
        db.session.add(new_user)
        db.session.commit()
        logger.debug(f"User registered: {data['email']}")
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to register user'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    logger.debug(f"Login data: {data}")
    if not data or 'email' not in data or 'password' not in data:
        logger.error("Invalid login payload")
        return jsonify({'error': 'Missing email or password'}), 400
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        logger.debug(f"No user found for email: {data['email']}")
        return jsonify({'error': 'Invalid credentials'}), 401
    try:
        if bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
            session['user_id'] = user.user_id
            logger.debug(f"Session created for user: {user.email}")
            return jsonify({'message': 'Login successful', 'role': user.role, 'name': user.name}), 200
        else:
            logger.debug(f"Password mismatch for user: {data['email']}")
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    logger.debug("User logged out")
    return jsonify({'message': 'Logout successful'}), 200

@app.route('/api/books', methods=['GET'])
def get_books():
    search = request.args.get('search', '')
    try:
        books = Book.query.filter(
            Book.title.ilike(f'%{search}%') | Book.author.ilike(f'%{search}%')
        ).all()
        logger.debug(f"Fetched {len(books)} books")
        return jsonify([{
            'book_id': b.book_id,
            'title': b.title,
            'author': b.author,
            'isbn': b.isbn,
            'category': b.category,
            'total_copies': b.total_copies,
            'available_copies': b.available_copies,
            'published_year': b.published_year
        } for b in books]), 200
    except Exception as e:
        logger.error(f"Error fetching books: {str(e)}")
        return jsonify({'error': 'Failed to fetch books'}), 500

@app.route('/api/books/status', methods=['GET'])
@login_required(role='student')
def get_book_status():
    user_id = session['user_id']
    try:
        # Fetch all books
        books = Book.query.all()
        # Fetch user's active transactions
        transactions = Transaction.query.filter_by(
            user_id=user_id
        ).filter(Transaction.status != 'returned').all()
        # Fetch user's active reservations
        reservations = Reservation.query.filter_by(
            user_id=user_id, status='active'
        ).all()
        
        book_statuses = []
        for book in books:
            status = 'available'
            # Check if the book is borrowed by the user
            if any(t.book_id == book.book_id for t in transactions):
                status = 'borrowed'
            # Check if the book is reserved by the user
            elif any(r.book_id == book.book_id for r in reservations):
                status = 'reserved'
            # Check if all copies are reserved
            active_reservations = Reservation.query.filter_by(
                book_id=book.book_id, status='active'
            ).count()
            if book.available_copies <= active_reservations and status != 'reserved':
                status = 'all_reserved'
                
            book_statuses.append({
                'book_id': book.book_id,
                'status': status,
                'available_copies': book.available_copies
            })
        logger.debug(f"Fetched book statuses for user_id={user_id}")
        return jsonify(book_statuses), 200
    except Exception as e:
        logger.error(f"Error fetching book statuses: {str(e)}")
        return jsonify({'error': 'Failed to fetch book statuses'}), 500

@app.route('/api/books', methods=['POST'])
@login_required(role='admin')
def add_book():
    user_id = session['user_id']
    data = request.get_json()
    logger.debug(f"Add book data: {data}")
    if not all(key in data for key in ['title', 'author', 'isbn', 'total_copies']):
        logger.error("Missing required fields")
        return jsonify({'error': 'Missing required fields'}), 400
    if Book.query.filter_by(isbn=data['isbn']).first():
        logger.debug(f"Duplicate ISBN: {data['isbn']}")
        return jsonify({'error': 'A book with this ISBN already exists'}), 400
    try:
        new_book = Book(
            title=data['title'],
            author=data['author'],
            isbn=data['isbn'],
            category=data.get('category'),
            total_copies=data['total_copies'],
            available_copies=data['total_copies'],
            published_year=data.get('published_year')
        )
        db.session.add(new_book)
        db.session.commit()
        logger.debug(f"Book added: {data['title']} (ISBN: {data['isbn']})")
        book = Book.query.filter_by(isbn=data['isbn']).first()
        if book:
            logger.debug(f"Verified book in DB: {book.title} (book_id: {book.book_id})")
        else:
            logger.error("Book not found in DB after commit")
        return jsonify({'message': 'Book added successfully'}), 201
    except Exception as e:
        logger.error(f"Error adding book: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to add book'}), 500

@app.route('/api/books/<int:book_id>', methods=['PUT'])
@login_required(role='admin')
def edit_book(book_id):
    user_id = session['user_id']
    data = request.get_json()
    logger.debug(f"Edit book data: {data} for book_id={book_id}")
    if not all(key in data for key in ['title', 'author', 'isbn', 'total_copies']):
        logger.error("Missing required fields")
        return jsonify({'error': 'Missing required fields'}), 400
    book = Book.query.get(book_id)
    if not book:
        logger.debug(f"Book not found: book_id={book_id}")
        return jsonify({'error': 'Book not found'}), 404
    if Book.query.filter_by(isbn=data['isbn']).filter(Book.book_id != book_id).first():
        logger.debug(f"Duplicate ISBN: {data['isbn']}")
        return jsonify({'error': 'A book with this ISBN already exists'}), 400
    try:
        book.title = data['title']
        book.author = data['author']
        book.isbn = data['isbn']
        book.category = data.get('category')
        current_borrowed = book.total_copies - book.available_copies
        new_total_copies = data['total_copies']
        if new_total_copies < current_borrowed:
            logger.error(f"Cannot reduce total copies below borrowed copies: {current_borrowed}")
            return jsonify({'error': 'Cannot reduce total copies below borrowed copies'}), 400
        book.total_copies = new_total_copies
        book.available_copies = new_total_copies - current_borrowed
        book.published_year = data.get('published_year')
        db.session.commit()
        logger.debug(f"Book updated: book_id={book_id}")
        return jsonify({'message': 'Book updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error updating book: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update book'}), 500

@app.route('/api/books/<int:book_id>', methods=['DELETE'])
@login_required(role='admin')
def delete_book(book_id):
    user_id = session['user_id']
    book = Book.query.get(book_id)
    if not book:
        logger.debug(f"Book not found: book_id={book_id}")
        return jsonify({'error': 'Book not found'}), 404
    try:
        db.session.delete(book)
        db.session.commit()
        logger.debug(f"Book deleted: book_id={book_id}")
        return jsonify({'message': 'Book deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting book: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete book'}), 500

@app.route('/api/books/borrow', methods=['POST'])
@login_required()
def borrow_book():
    user_id = session['user_id']
    data = request.get_json()
    if not data or 'book_id' not in data:
        logger.error("Missing book_id")
        return jsonify({'error': 'Missing book_id'}), 400
    book = Book.query.get(data['book_id'])
    if not book or book.available_copies == 0:
        logger.debug(f"Book unavailable: book_id={data['book_id']}")
        return jsonify({'error': 'Book unavailable'}), 400
    # Check active reservations for the book
    active_reservations = Reservation.query.filter_by(
        book_id=data['book_id'], status='active'
    ).count()
    # Check if the user has an active reservation for this book
    user_reservation = Reservation.query.filter_by(
        book_id=data['book_id'], user_id=user_id, status='active'
    ).first()
    # Allow borrowing if there are unreserved copies or the user has a reservation
    if book.available_copies <= active_reservations and not user_reservation:
        logger.debug(f"All copies reserved: book_id={data['book_id']}")
        return jsonify({'error': 'All copies are reserved by other users'}), 403
    try:
        # Cancel the user's reservation if they are borrowing
        if user_reservation:
            user_reservation.status = 'cancelled'
        book.available_copies -= 1
        due_date = datetime.utcnow().date() + timedelta(days=14)
        transaction = Transaction(
            user_id=user_id,
            book_id=data['book_id'],
            due_date=due_date,
            status='borrowed'
        )
        db.session.add(transaction)
        db.session.commit()
        logger.debug(f"Book borrowed: book_id={data['book_id']} by user_id={user_id}")
        trans = Transaction.query.filter_by(user_id=user_id, book_id=data['book_id'], return_date=None).first()
        if trans:
            logger.debug(f"Verified transaction in DB: transaction_id={trans.transaction_id}")
        else:
            logger.error("Transaction not found in DB after commit")
        return jsonify({'message': 'Book borrowed successfully'}), 201
    except Exception as e:
        logger.error(f"Error borrowing book: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to borrow book'}), 500

@app.route('/api/books/return', methods=['POST'])
@login_required()
def return_book():
    user_id = session['user_id']
    data = request.get_json()
    if not data or 'transaction_id' not in data:
        logger.error("Missing transaction_id")
        return jsonify({'error': 'Missing transaction_id'}), 400
    transaction = Transaction.query.filter_by(
        transaction_id=data['transaction_id'],
        user_id=user_id
    ).first()
    if not transaction or transaction.return_date:
        logger.debug(f"Invalid transaction: transaction_id={data['transaction_id']}")
        return jsonify({'error': 'Invalid or already returned transaction'}), 400
    try:
        transaction.return_date = datetime.utcnow().date()
        transaction.status = 'pending_approval'
        transaction.fine_amount = 0.0  # Fine calculated on approval
        book = Book.query.get(transaction.book_id)
        book.available_copies += 1
        db.session.commit()
        logger.debug(f"Book return requested: transaction_id={data['transaction_id']}")
        return jsonify({
            'message': 'Book return requested, pending admin approval',
            'fine_amount': transaction.fine_amount
        }), 200
    except Exception as e:
        logger.error(f"Error returning book: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to request book return'}), 500

@app.route('/api/transactions/approve', methods=['POST'])
@login_required(role='admin')
def approve_return():
    user_id = session['user_id']
    data = request.get_json()
    if not data or 'transaction_id' not in data:
        logger.error("Missing transaction_id")
        return jsonify({'error': 'Missing transaction_id'}), 400
    transaction = Transaction.query.get(data['transaction_id'])
    if not transaction or transaction.status != 'pending_approval':
        logger.debug(f"Invalid transaction for approval: transaction_id={data['transaction_id']}")
        return jsonify({'error': 'Invalid or already processed transaction'}), 400
    try:
        days_overdue = (transaction.return_date - transaction.due_date).days
        if days_overdue > 0:
            transaction.fine_amount = days_overdue * 1.0
        else:
            transaction.fine_amount = 0.0
        transaction.status = 'returned'
        db.session.commit()
        logger.debug(f"Return approved: transaction_id={data['transaction_id']}")
        return jsonify({
            'message': 'Return approved successfully',
            'fine_amount': transaction.fine_amount
        }), 200
    except Exception as e:
        logger.error(f"Error approving return: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to approve return'}), 500

@app.route('/api/books/reserve', methods=['POST'])
@login_required(role='student')
def reserve_book():
    user_id = session['user_id']
    data = request.get_json()
    if not data or 'book_id' not in data:
        logger.error("Missing book_id")
        return jsonify({'error': 'Missing book_id'}), 400
    book = Book.query.get(data['book_id'])
    if not book:
        logger.debug(f"Book not found: book_id={data['book_id']}")
        return jsonify({'error': 'Book not found'}), 404
    if book.available_copies > 0:
        logger.debug(f"Book is available: book_id={data['book_id']}")
        return jsonify({'error': 'Book is currently available for borrowing'}), 400
    # Check if user already has an active reservation for this book
    existing_reservation = Reservation.query.filter_by(
        user_id=user_id, book_id=data['book_id'], status='active'
    ).first()
    if existing_reservation:
        logger.debug(f"User already reserved book: book_id={data['book_id']}")
        return jsonify({'error': 'You have already reserved this book'}), 400
    try:
        reservation = Reservation(
            user_id=user_id,
            book_id=data['book_id'],
            reservation_date=datetime.utcnow().date(),
            status='active'
        )
        db.session.add(reservation)
        db.session.commit()
        logger.debug(f"Book reserved: book_id={data['book_id']} by user_id={user_id}")
        return jsonify({'message': 'Book reserved successfully'}), 201
    except Exception as e:
        logger.error(f"Error reserving book: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to reserve book'}), 500

@app.route('/api/reservations', methods=['GET'])
@login_required()
def get_reservations():
    user_id = session['user_id']
    user = User.query.get(user_id)
    try:
        if user.role == 'admin':
            reservations = Reservation.query.filter_by(status='active').join(User).join(Book).all()
        else:
            reservations = Reservation.query.filter_by(
                user_id=user_id, status='active'
            ).join(Book).all()
        logger.debug(f"Fetched {len(reservations)} reservations for user_id={user_id}")
        return jsonify([{
            'reservation_id': r.reservation_id,
            'user_name': r.user.name if user.role == 'admin' else None,
            'book_id': r.book.book_id,
            'book_title': r.book.title,
            'reservation_date': r.reservation_date.isoformat(),
            'status': r.status,
            'available_copies': r.book.available_copies
        } for r in reservations]), 200
    except Exception as e:
        logger.error(f"Error fetching reservations: {str(e)}")
        return jsonify({'error': 'Failed to fetch reservations'}), 500

@app.route('/api/transactions', methods=['GET'])
@login_required()
def get_transactions():
    user_id = session['user_id']
    user = User.query.get(user_id)
    try:
        if user.role == 'admin':
            transactions = Transaction.query.join(User).join(Book).all()
        else:
            transactions = Transaction.query.filter_by(
                user_id=user_id
            ).join(User).join(Book).all()
        logger.debug(f"Fetched {len(transactions)} transactions for user_id={user_id}")
        return jsonify([{
            'transaction_id': t.transaction_id,
            'user_name': t.user.name,
            'book_id': t.book.book_id,
            'book_title': t.book.title,
            'issue_date': t.issue_date.isoformat(),
            'due_date': t.due_date.isoformat(),
            'return_date': t.return_date.isoformat() if t.return_date else None,
            'fine_amount': float(t.fine_amount),
            'status': t.status
        } for t in transactions]), 200
    except Exception as e:
        logger.error(f"Error fetching transactions: {str(e)}")
        return jsonify({'error': 'Failed to fetch transactions'}), 500

# Error handler
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {str(error)}")
    return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)