from flask import Flask, render_template, request, jsonify, flash, redirect, session, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Length
from models import db, User
from config import Config
from flask_migrate import Migrate
from sqlalchemy import text
import os
import logging
from logging.handlers import RotatingFileHandler
from werkzeug.middleware.proxy_fix import ProxyFix

# Initialize Flask app
app = Flask(__name__, 
    static_folder='assets', 
    static_url_path='/assets',
    template_folder='templates'  # Explicitly set template folder
)

# Load configuration
app.config.from_object(Config)

# Initialize database
db.init_app(app)
migrate = Migrate(app, db)

# Set up logging
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# Production settings
if os.environ.get('FLASK_ENV') == 'production':
    # Security settings
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    
    # Enhanced logging configuration
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/genix.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] - %(message)s'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    # Also log to console in production
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] - %(message)s'
    ))
    console_handler.setLevel(logging.INFO)
    app.logger.addHandler(console_handler)
    
    app.logger.info('=== Application Started in Production Mode ===')
    app.logger.info('Database URI: %s', app.config['SQLALCHEMY_DATABASE_URI'].replace(
        app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0], '***'
    ))

# Add a test route to verify the app is working
@app.route('/test')
def test():
    app.logger.info('Test route accessed')
    return jsonify({
        'status': 'ok',
        'message': 'Flask app is working!',
        'environment': os.environ.get('FLASK_ENV', 'development')
    })

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
    app.logger.info('=== Signin Route Accessed ===')
    app.logger.info('Method: %s', request.method)
    app.logger.info('Headers: %s', dict(request.headers))
    
    form = LoginForm()
    if request.method == 'POST':
        app.logger.info('Signin attempt from IP: %s', request.remote_addr)
        
        try:
            if request.is_json:
                json_data = request.get_json()
                app.logger.info('Received JSON data: %s', json_data)
                for field in form:
                    if field.name in json_data:
                        field.data = json_data[field.name]
                        app.logger.info('Set form field %s to %s', field.name, field.data)
            else:
                app.logger.info('Form data: %s', request.form)
            
            app.logger.info('Validating form...')
            if form.validate_on_submit():
                app.logger.info('Form validation successful')
                try:
                    app.logger.info('Attempting to find user with email: %s', form.email.data)
                    user = User.query.filter_by(email=form.email.data).first()
                    
                    if user:
                        app.logger.info('User found with ID: %s', user.id)
                        app.logger.info('Checking password...')
                        if user.check_password(form.password.data):
                            app.logger.info('Password check successful')
                            if user.role == form.role.data:
                                app.logger.info('Role check successful. Setting session...')
                                session['user_id'] = user.id
                                session['user_role'] = user.role
                                session['user_email'] = user.email
                                app.logger.info('Session set successfully: %s', dict(session))
                                
                                return jsonify({
                                    'message': 'Login successful!',
                                    'redirect': '/'
                                }), 200
                            else:
                                app.logger.warning('Role mismatch. User role: %s, Requested role: %s', 
                                                 user.role, form.role.data)
                                return jsonify({'error': 'Invalid role for this account'}), 401
                        else:
                            app.logger.warning('Password check failed for user: %s', user.email)
                            return jsonify({'error': 'Invalid email or password'}), 401
                    else:
                        app.logger.warning('No user found with email: %s', form.email.data)
                        return jsonify({'error': 'Invalid email or password'}), 401
                        
                except Exception as e:
                    app.logger.error('Database error during login: %s', str(e), exc_info=True)
                    return jsonify({'error': 'Login failed. Please try again.'}), 500
            else:
                app.logger.warning('Form validation failed: %s', form.errors)
                return jsonify({
                    'error': 'Invalid form data',
                    'errors': form.errors
                }), 400
                
        except Exception as e:
            app.logger.error('Unexpected error during login: %s', str(e), exc_info=True)
            return jsonify({'error': 'An unexpected error occurred'}), 500
            
    app.logger.info('Rendering signin template')
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
    # For local development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=(os.environ.get('FLASK_ENV') != 'production'))

