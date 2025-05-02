from app import app, db, User, Book, Transaction
from datetime import datetime, timedelta
import bcrypt

with app.app_context():
    # Reset the database
    db.drop_all()
    db.create_all()
    print("🔄 Database reset")

    # Insert Users
    users = [
        {"name": "Admin User", "email": "admin@example.com", "password": "admin123", "role": "admin"},
        {"name": "Student One", "email": "student1@example.com", "password": "student123", "role": "student"},
        {"name": "Student Two", "email": "student2@example.com", "password": "student123", "role": "student"}
    ]

    for u in users:
        hashed_pw = bcrypt.hashpw(u["password"].encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        user = User(name=u["name"], email=u["email"], password=hashed_pw, role=u["role"])
        db.session.add(user)

    db.session.commit()
    print("✅ Users inserted")

    # Insert Books
    books = [
        {"title": "Python Programming", "author": "John Zelle", "isbn": "9781590282410", "category": "Programming", "total_copies": 5, "published_year": 2017},
        {"title": "Flask Web Development", "author": "Miguel Grinberg", "isbn": "9781491991732", "category": "Web", "total_copies": 3, "published_year": 2018},
        {"title": "Clean Code", "author": "Robert C. Martin", "isbn": "9780132350884", "category": "Software", "total_copies": 2, "published_year": 2008}
    ]

    for b in books:
        book = Book(
            title=b["title"],
            author=b["author"],
            isbn=b["isbn"],
            category=b["category"],
            total_copies=b["total_copies"],
            available_copies=b["total_copies"],
            published_year=b["published_year"]
        )
        db.session.add(book)

    db.session.commit()
    print("✅ Books inserted")

    # Insert a sample Transaction
    student = User.query.filter_by(email="student1@example.com").first()
    book = Book.query.filter_by(title="Python Programming").first()

    if student and book and book.available_copies > 0:
        transaction = Transaction(
            user_id=student.user_id,
            book_id=book.book_id,
            issue_date=datetime.utcnow().date(),
            due_date=datetime.utcnow().date() + timedelta(days=14),
            status='borrowed'
        )
        db.session.add(transaction)
        book.available_copies -= 1
        db.session.commit()
        print(f"✅ Transaction inserted: {student.name} borrowed '{book.title}'")

    else:
        print("⚠️ Could not insert transaction (missing user/book or no available copies)")
