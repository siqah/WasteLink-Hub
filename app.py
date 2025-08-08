from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import os
from sqlalchemy import inspect

app = Flask(__name__)

# Configure database URI
# Use DATABASE_URL from environment variables if available, otherwise fall back to SQLite
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///wastelink.db'

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here-for-dev')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure tables exist on startup (useful on Render free tier without shell)
with app.app_context():
    try:
        inspector = inspect(db.engine)
        # Create tables if they don't exist
        if not inspector.has_table('users') or not inspector.has_table('pickup_requests'):
            db.create_all()
    except Exception:
        # Avoid breaking app startup if DB is temporarily unavailable
        pass


# Models
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'household', 'collector', 'business', 'recycling_center'
    address = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    pickups_requested = db.relationship('PickupRequest', foreign_keys='PickupRequest.user_id', backref='requester', lazy=True)
    pickups_collected = db.relationship('PickupRequest', foreign_keys='PickupRequest.collector_id', backref='collector', lazy=True)

    # Collector-specific fields
    vehicle_info = db.Column(db.String(100))
    service_area = db.Column(db.String(100))
    
    # Business/Recycling Center fields
    business_name = db.Column(db.String(100))
    business_type = db.Column(db.String(50))
    materials_accepted = db.Column(db.String(200))
    operating_hours = db.Column(db.String(100))

class PickupRequest(db.Model):
    __tablename__ = 'pickup_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    collector_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    scheduled_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, completed, cancelled
    waste_type = db.Column(db.String(50), nullable=False)
    waste_description = db.Column(db.String(200))
    special_instructions = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completion_date = db.Column(db.DateTime)

# Ensure tables exist when the first request hits the app (helps if DB was not ready at startup)
@app.before_first_request
def ensure_tables_created():
    try:
        db.create_all()
    except Exception as e:
        app.logger.error(f"DB init on first request failed: {e}")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    if len(password) < 8:
        return False
    return True

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        
        # Additional fields based on role
        business_name = request.form.get('business_name', '')
        vehicle_info = request.form.get('vehicle_info', '')
        service_area = request.form.get('service_area', '')
        materials_accepted = request.form.get('materials_accepted', '')
        
        # Validation
        if not all([username, email, password, confirm_password, role]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
            
        if not validate_email(email):
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))
            
        if not validate_password(password):
            flash('Password must be at least 8 characters long', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role,
            phone=phone,
            address=address,
            business_name=business_name if role in ['business', 'recycling_center'] else None,
            vehicle_info=vehicle_info if role == 'collector' else None,
            service_area=service_area if role == 'collector' else None,
            materials_accepted=materials_accepted if role == 'recycling_center' else None
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
        
        login_user(user)
        
        flash('Login successful!', 'success')
        
        # Redirect based on role
        if user.role == 'collector':
            return redirect(url_for('collector_dashboard'))
        elif user.role in ['business', 'household']:
            return redirect(url_for('client_dashboard'))
        elif user.role == 'recycling_center':
            return redirect(url_for('recycling_center_dashboard'))
        
        return redirect(url_for('home'))
    
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def client_dashboard():
    return render_template('dashboard/client.html', user=current_user)

@app.route('/collector/dashboard')
@login_required
def collector_dashboard():
    if current_user.role != 'collector':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    pending_requests = PickupRequest.query.filter_by(status='pending').all()
    return render_template('dashboard/collector.html', user=current_user, requests=pending_requests)

@app.route('/recycling-center-dashboard')
@login_required
def recycling_center_dashboard():
    if current_user.role != 'recycling_center':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    completed_pickups = PickupRequest.query.filter_by(status='completed').all()
    return render_template('dashboard/recycling_center_dashboard.html', pickups=completed_pickups)

@app.route('/request-pickup', methods=['GET', 'POST'])
@login_required
def request_pickup():
    if request.method == 'POST':
        scheduled_date_str = request.form.get('scheduled_date')
        waste_type = request.form.get('waste_type')
        
        if not scheduled_date_str or not waste_type:
            flash('Please provide both a date and a waste type.', 'error')
            return redirect(url_for('request_pickup'))

        try:
            scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date format. Please use the provided date picker.', 'error')
            return redirect(url_for('request_pickup'))

        if scheduled_date < datetime.now():
            flash('Pickup date cannot be in the past.', 'error')
            return redirect(url_for('request_pickup'))

        waste_description = request.form.get('waste_description', '')
        special_instructions = request.form.get('special_instructions', '')
        
        new_request = PickupRequest(
            user_id=current_user.id,
            scheduled_date=scheduled_date,
            waste_type=waste_type,
            waste_description=waste_description,
            special_instructions=special_instructions,
            status='pending'
        )
        
        db.session.add(new_request)
        db.session.commit()
        flash('Pickup request submitted successfully!', 'success')
        return redirect(url_for('client_dashboard'))
    
    return render_template('pickup/request.html')

@app.route('/available-pickups')
@login_required
def available_pickups():
    if current_user.role != 'collector':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    pending_requests = PickupRequest.query.filter_by(status='pending', collector_id=None).all()
    return render_template('pickup/available.html', requests=pending_requests)

@app.route('/my-pickups')
@login_required
def my_pickups():
    if current_user.role != 'collector':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    
    accepted_requests = PickupRequest.query.filter_by(collector_id=current_user.id, status='accepted').all()
    return render_template('pickup/my_pickups.html', requests=accepted_requests)

@app.route('/complete-pickup/<int:request_id>', methods=['POST'])
@login_required
def complete_pickup(request_id):
    if current_user.role != 'collector':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    pickup_request = PickupRequest.query.get_or_404(request_id)

    if pickup_request.collector_id != current_user.id:
        flash('You are not authorized to complete this request.', 'danger')
        return redirect(url_for('my_pickups'))

    pickup_request.status = 'completed'
    pickup_request.completion_date = datetime.utcnow()
    db.session.commit()

    flash('Pickup marked as completed!', 'success')
    return redirect(url_for('my_pickups'))

@app.route('/accept-request/<int:request_id>', methods=['POST'])
@login_required
def accept_request(request_id):
    if current_user.role != 'collector':
        flash('You must be logged in as a collector to perform this action.', 'error')
        return redirect(url_for('login'))
    
    pickup = PickupRequest.query.get_or_404(request_id)
    
    if pickup.status != 'pending':
        flash('This request has already been processed', 'error')
        return redirect(url_for('collector_dashboard'))
    
    pickup.status = 'accepted'
    pickup.collector_id = current_user.id
    db.session.commit()
    
    flash('Pickup request accepted!', 'success')
    return redirect(url_for('collector_dashboard'))