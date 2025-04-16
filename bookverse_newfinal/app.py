import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()  # Secure random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "instance", "database.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'static', 'images')
db = SQLAlchemy(app)

# Enable foreign key support for SQLite
from sqlalchemy import event
from sqlite3 import Connection as SQLite3Connection

with app.app_context():
    @event.listens_for(db.engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        if isinstance(dbapi_connection, SQLite3Connection):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_image_url = db.Column(db.String(200), nullable=True)  # New field for profile image
    books = db.relationship('Book', backref='seller', lazy=True, foreign_keys='Book.seller_id')
    book_requests = db.relationship('BookRequest', backref='requester', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(80), nullable=False)
    condition = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Float, nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='available')
    contact_details = db.Column(db.String(200), nullable=True)
    reviews = db.relationship('Review', backref='book', lazy=True, cascade="all, delete-orphan")
    reports = db.relationship('Report', backref='book', lazy=True, cascade="all, delete-orphan")
    image_url = db.Column(db.String(200), nullable=True)

    @property
    def avg_rating(self):
        if not self.reviews:
            return 0
        return sum(review.rating for review in self.reviews) / len(self.reviews)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    user = db.relationship('User', backref='reports', lazy=True)

class BookRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    condition = db.Column(db.String(20), nullable=False)
    image_url = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# Create the database
with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def home():
    search = request.args.get('search', '').lower()
    sort = request.args.get('sort', 'relevance')
    min_price = request.args.get('min-price', type=float)
    max_price = request.args.get('max-price', type=float)
    ratings = request.args.getlist('rating')
    conditions = request.args.getlist('condition')

    query = Book.query.filter_by(status='available')

    if search:
        query = query.filter(
            (Book.title.ilike(f'%{search}%')) |
            (Book.author.ilike(f'%{search}%'))
        )

    if min_price is not None:
        query = query.filter(Book.price >= min_price)
    if max_price is not None:
        query = query.filter(Book.price <= max_price)

    if conditions:
        query = query.filter(Book.condition.in_(conditions))

    books = query.all()
    if ratings:
        rating_values = [int(r) for r in ratings]
        min_rating = min(rating_values)
        books = [book for book in books if book.avg_rating >= min_rating]

    if sort == 'price_asc':
        books = sorted(books, key=lambda x: x.price)
    elif sort == 'price_desc':
        books = sorted(books, key=lambda x: x.price, reverse=True)
    elif sort == 'rating_desc':
        books = sorted(books, key=lambda x: x.avg_rating, reverse=True)

    return render_template('home.html', books=books, sort=sort)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('admin_id', None)  # Clear admin session too if present
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not (username and password):
            flash('Username and password are required.', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        user = User(username=username, password=generate_password_hash(password))
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('register.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        logger.debug(f"Admin login attempt: username={username}")
        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and check_password_hash(user.password, password):
            session['admin_id'] = user.id
            logger.debug(f"Admin login successful: admin_id={user.id}")
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials.', 'error')
        logger.debug("Admin login failed: invalid credentials")
    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_id', None)
    flash('Logged out successfully.', 'success')
    logger.debug("Admin logged out")
    return redirect(url_for('admin_login'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_id' not in session:
        logger.debug("No admin_id in session, redirecting to admin_login")
        flash('Please log in as an admin to access this page.', 'error')
        return redirect(url_for('admin_login'))
    
    try:
        book_requests = BookRequest.query.filter_by(status='pending').all()
        logger.debug(f"Book Requests: {len(book_requests)} found")

        reports = Report.query.filter_by(status='pending').all()
        reports = [report for report in reports if report.book is not None]
        logger.debug(f"Reports: {len(reports)} found after filtering")

        books = Book.query.all()
        logger.debug(f"Books: {len(books)} found")

        if request.method == 'POST' and 'book_id' in request.form:
            book_id = request.form.get('book_id', type=int)
            if not book_id:
                flash('Invalid book ID.', 'error')
                logger.debug("Invalid book_id in POST request")
                return redirect(url_for('admin_dashboard'))
            
            book = Book.query.get_or_404(book_id)
            db.session.delete(book)
            db.session.commit()
            flash('Book removed successfully!', 'success')
            logger.debug(f"Book {book_id} removed successfully")
            return redirect(url_for('admin_dashboard'))

    except Exception as e:
        logger.error(f"Error in admin_dashboard: {str(e)}")
        db.session.rollback()
        flash('An unexpected error occurred. Please try again later.', 'error')
        return redirect(url_for('admin_dashboard'))

    logger.debug("Rendering admin_dashboard.html")
    return render_template('admin_dashboard.html', books=books, reports=reports, book_requests=book_requests)

@app.route('/approve_book_request/<int:request_id>', methods=['POST'])
def approve_book_request(request_id):
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'error')
        return redirect(url_for('admin_login'))
    
    try:
        book_request = BookRequest.query.get_or_404(request_id)
        book = Book(
            title=book_request.title,
            author=book_request.author,
            condition=book_request.condition,
            price=book_request.price,
            seller_id=book_request.user_id if book_request.user_id else 1,
            status='available',
            image_url=book_request.image_url
        )
        db.session.add(book)
        book_request.status = 'approved'
        db.session.commit()
        flash('Book request approved and added to the database.', 'success')
        logger.debug(f"Book request {request_id} approved")
    except Exception as e:
        logger.error(f"Error approving book request {request_id}: {str(e)}")
        db.session.rollback()
        flash('An error occurred while approving the book request.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/reject_book_request/<int:request_id>', methods=['POST'])
def reject_book_request(request_id):
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'error')
        return redirect(url_for('admin_login'))
    
    try:
        book_request = BookRequest.query.get_or_404(request_id)
        Book_request.status = 'rejected'
        db.session.commit()
        flash('Book request rejected.', 'success')
        logger.debug(f"Book request {request_id} rejected")
    except Exception as e:
        logger.error(f"Error rejecting book request {request_id}: {str(e)}")
        db.session.rollback()
        flash('An error occurred while rejecting the book request.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/remove_reported_book/<int:report_id>', methods=['POST'])
def remove_reported_book(report_id):
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'error')
        return redirect(url_for('admin_login'))
    
    try:
        report = Report.query.get_or_404(report_id)
        book = Book.query.get_or_404(report.book_id)
        db.session.delete(book)
        db.session.commit()
        flash('Book and associated reports removed successfully.', 'success')
        logger.debug(f"Reported book for report {report_id} removed")
    except Exception as e:
        logger.error(f"Error removing reported book for report {report_id}: {str(e)}")
        db.session.rollback()
        flash('An error occurred while removing the book.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_review', methods=['GET', 'POST'])
@app.route('/add_review', methods=['GET', 'POST'])
def add_review():
    books = Book.query.all()
    if request.method == 'POST':
        try:
            if 'submit_review' in request.form:
                book_id = request.form.get('book_id')
                rating = request.form.get('rating')
                text = request.form.get('text')
                if not (book_id and rating and text):
                    flash('All fields are required.', 'error')
                    return redirect(url_for('add_review'))
                rating = int(rating)
                if rating < 1 or rating > 5:
                    flash('Rating must be between 1 and 5.', 'error')
                    return redirect(url_for('add_review'))
                review = Review(book_id=book_id, rating=rating, text=text)
                db.session.add(review)
                
                # Fetch the book and notify the seller
                book = Book.query.get(book_id)
                if book.seller_id:
                    notification = Notification(
                        user_id=book.seller_id,
                        message=f"A new review has been added to your book '{book.title}'!"
                    )
                    db.session.add(notification)
                    logger.debug(f"Notification created for user {book.seller_id} about review on book {book.id}")
                
                db.session.commit()
                flash('Review added successfully!', 'success')
                return redirect(url_for('home'))
            # ... (rest of the route remains unchanged)
            elif 'request_book' in request.form:
                title = request.form.get('title')
                author = request.form.get('author')
                price = request.form.get('price')
                condition = request.form.get('condition')
                image = request.files.get('image')
                
                if not (title and author and price and condition):
                    flash('All fields (title, author, price, condition) are required.', 'error')
                    return redirect(url_for('add_review'))
                
                price = float(price)
                if price < 0:
                    flash('Price cannot be negative.', 'error')
                    return redirect(url_for('add_review'))
                
                image_url = None
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    image.save(image_path)
                    image_url = f"/static/images/{filename}"
                
                book_request = BookRequest(
                    title=title,
                    author=author,
                    price=price,
                    condition=condition,
                    image_url=image_url,
                    user_id=session.get('user_id'),
                    status='pending'
                )
                db.session.add(book_request)
                db.session.commit()
                flash('Book request submitted successfully. It will be reviewed by an admin.', 'success')
                return redirect(url_for('add_review'))
        except ValueError:
            flash('Invalid input (e.g., rating or price must be a number).', 'error')
            return redirect(url_for('add_review'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('add_review'))
    return render_template('add_review.html', books=books)

@app.route('/book/<int:book_id>', methods=['GET', 'POST'])
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    reviews = Review.query.filter_by(book_id=book_id).all()
    if request.method == 'POST':
        rating = request.form.get('rating')
        text = request.form.get('text')
        if not (rating and text):
            flash('Rating and review text are required.', 'error')
            return redirect(url_for('book_detail', book_id=book_id))
        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                flash('Rating must be between 1 and 5.', 'error')
                return redirect(url_for('book_detail', book_id=book_id))
            review = Review(book_id=book.id, rating=rating, text=text)
            db.session.add(review)
            
            # Create notification for the seller
            if book.seller_id:
                notification = Notification(
                    user_id=book.seller_id,
                    message=f"A new review has been added to your book '{book.title}'!"
                )
                db.session.add(notification)
                logger.debug(f"Notification created for user {book.seller_id} about review on book {book.id}")
            
            db.session.commit()
            flash('Review added successfully!', 'success')
        except ValueError:
            flash('Invalid rating value.', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('book_detail', book_id=book.id))
    return render_template('book_detail.html', book=book, reviews=reviews)

@app.route('/sell_book', methods=['GET', 'POST'])
def sell_book():
    if 'user_id' not in session:
        flash('Please log in to sell a book.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        condition = request.form.get('condition')
        price = request.form.get('price')
        contact_details = request.form.get('contact_details')
        image = request.files.get('image')
        
        # Image is optional, so only check required fields
        if not (title and author and condition and price and contact_details):
            flash('Title, author, condition, price, and contact details are required.', 'error')
            return redirect(url_for('sell_book'))
        
        try:
            price = float(price)
            if price < 0:
                flash('Price cannot be negative.', 'error')
                return redirect(url_for('sell_book'))
            
            image_url = None
            if image and image.filename and allowed_file(image.filename):  # Check if image is provided and valid
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = f"/static/images/{filename}"
            
            book = Book(
                title=title,
                author=author,
                condition=condition,
                price=price,
                seller_id=session['user_id'],
                contact_details=contact_details,
                image_url=image_url
            )
            db.session.add(book)
            db.session.commit()
            flash('Book listed for sale successfully!', 'success')
            return redirect(url_for('home'))
        except ValueError:
            flash('Invalid price value.', 'error')
            return redirect(url_for('sell_book'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('sell_book'))
    return render_template('sell_book.html')

@app.route('/buy_book', methods=['GET', 'POST'])
def buy_book():
    books = Book.query.filter_by(status='available').all()
    purchased_book = None
    
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('Please log in to buy a book.', 'error')
            return redirect(url_for('login'))
        
        book_id = request.form.get('book_id')
        book = Book.query.get_or_404(book_id)
        
        if book.status != 'available':
            flash('This book is no longer available.', 'error')
            return redirect(url_for('buy_book'))
        
        try:
            book.buyer_id = session['user_id']
            book.status = 'sold'
            db.session.commit()
            purchased_book = book
            flash('Book purchased successfully! Contact the seller below.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('buy_book.html', books=books, purchased_book=purchased_book)

@app.route('/report_book', methods=['POST'])
def report_book():
    book_id = request.form.get('book_id')
    reason = request.form.get('reason')

    if not (book_id and reason):
        flash('Book ID and reason are required.', 'error')
        return redirect(url_for('buy_book'))

    book = Book.query.get_or_404(book_id)
    user_id = session.get('user_id')

    report = Report(
        book_id=book_id,
        user_id=user_id,
        reason=reason,
        status='pending'
    )
    try:
        db.session.add(report)
        db.session.commit()
        flash('Book reported successfully. It will be reviewed by an admin.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('buy_book'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    purchased_books = Book.query.filter_by(buyer_id=user.id, status='sold').all()
    sold_books = Book.query.filter_by(seller_id=user.id, status='sold').all()
    notifications = Notification.query.filter_by(user_id=user.id, is_read=False).order_by(Notification.created_at.desc()).all()
    
    return render_template('profile.html', user=user, purchased_books=purchased_books, 
                          sold_books=sold_books, notifications=notifications)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    if 'user_id' not in session:
        flash('Please log in to manage notifications.', 'error')
        return redirect(url_for('login'))
    
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != session['user_id']:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('profile'))
    
    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('profile'))

@app.route('/upload_profile_image', methods=['POST'])
def upload_profile_image():
    if 'user_id' not in session:
        flash('Please log in to upload a profile image.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    image = request.files.get('profile_image')
    
    if image and image.filename and allowed_file(image.filename):
        filename = secure_filename(f"profile_{user.id}_{image.filename}")
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user.profile_image_url = f"/static/images/{filename}"
        try:
            db.session.commit()
            flash('Profile image uploaded successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading profile image: {str(e)}', 'error')
    else:
        flash('No valid image selected or invalid format. Allowed: png, jpg, jpeg, gif.', 'error')
    
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)