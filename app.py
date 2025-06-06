from flask import Flask, render_template, request, jsonify, flash, redirect, session, url_for, send_from_directory
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Length
from models import db, User
from config import Config
from flask_migrate import Migrate
from sqlalchemy import text
import os

# Initialize Flask app
app = Flask(__name__, 
    static_folder='assets',
    static_url_path='/assets',
    static_host=None  # This ensures static files are served from the same domain
)

# Load configuration
app.config.from_object(Config)

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Configure session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Add a route to serve static files (as a fallback)
@app.route('/assets/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    phone = StringField('Phone', validators=[DataRequired(), Length(min=10, max=10)])
    country_code = SelectField('Country Code', choices=[('+1', '+1 USA')], validators=[DataRequired()])
    role = SelectField('Role', choices=[('doctor', 'Doctor'), ('patient', 'Patient'), ('admin', 'Admin')], validators=[DataRequired()])

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('doctor', 'Doctor'), ('patient', 'Patient'), ('admin', 'Admin')], validators=[DataRequired()])

@app.route('/')
def home():
    app.logger.info('Home page accessed')
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if request.method == 'POST':
        app.logger.info('Signup attempt from IP: %s', request.remote_addr)
        
        if request.is_json:
            json_data = request.get_json()
            for field in form:
                if field.name in json_data:
                    field.data = json_data[field.name]
        
        if form.validate_on_submit():
            try:
                if User.query.filter_by(email=form.email.data).first():
                    app.logger.warning('Duplicate email registration attempt: %s', form.email.data)
                    return jsonify({'error': 'Email already registered'}), 400
                
                user = User(
                    first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    email=form.email.data,
                    phone=form.phone.data,
                    country_code=form.country_code.data,
                    role=form.role.data
                )
                user.set_password(form.password.data)
                
                db.session.add(user)
                db.session.commit()
                app.logger.info('New user registered: %s', user.email)
                
                return jsonify({'message': 'Registration successful! Please sign in.'}), 200
            except Exception as e:
                db.session.rollback()
                app.logger.error('Registration error: %s', str(e))
                return jsonify({'error': 'Registration failed. Please try again.'}), 500
        else:
            app.logger.warning('Form validation failed: %s', form.errors)
            return jsonify({
                'error': 'Invalid form data',
                'errors': form.errors
            }), 400
            
    return render_template('signup.html', form=form)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = LoginForm()
    if request.method == 'POST':
        app.logger.info('Signin attempt from IP: %s', request.remote_addr)
        
        if request.is_json:
            json_data = request.get_json()
            for field in form:
                if field.name in json_data:
                    field.data = json_data[field.name]
        
        if form.validate_on_submit():
            try:
                user = User.query.filter_by(email=form.email.data).first()
                
                if user and user.check_password(form.password.data):
                    if user.role == form.role.data:
                        session['user_id'] = user.id
                        session['user_role'] = user.role
                        session['user_email'] = user.email
                        app.logger.info('User logged in: %s', user.email)
                        
                        return jsonify({
                            'message': 'Login successful!',
                            'redirect': '/'
                        }), 200
                    else:
                        app.logger.warning('Invalid role attempt for user: %s', user.email)
                        return jsonify({'error': 'Invalid role for this account'}), 401
                else:
                    app.logger.warning('Failed login attempt for email: %s', form.email.data)
                    return jsonify({'error': 'Invalid email or password'}), 401
                    
            except Exception as e:
                app.logger.error('Login error: %s', str(e))
                return jsonify({'error': 'Login failed. Please try again.'}), 500
        else:
            app.logger.warning('Login form validation failed: %s', form.errors)
            return jsonify({
                'error': 'Invalid form data',
                'errors': form.errors
            }), 400
            
    return render_template('signin.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'user_email' in session:
        app.logger.info('User logged out: %s', session['user_email'])
    
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('user_role', None)
    session.clear()
    session.modified = True

    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('signin'))

# Health check endpoint for monitoring
@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected'
        }), 200
    except Exception as e:
        app.logger.error('Health check failed: %s', str(e))
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/test-db-connection')
def test_db_connection():
    try:
        # Try to connect to the database using text()
        db.session.execute(text('SELECT 1'))
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Database connection successful',
            'database_url': str(app.config['SQLALCHEMY_DATABASE_URI']).replace(app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0], '***')
        }), 200
    except Exception as e:
        app.logger.error('Database connection test failed: %s', str(e))
        return jsonify({
            'status': 'error',
            'message': str(e),
            'database_url': str(app.config['SQLALCHEMY_DATABASE_URI']).replace(app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0], '***')
        }), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)

# For Vercel
app = app

