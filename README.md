# Genix.ai Web Application

A Flask-based web application with PostgreSQL database, featuring user authentication and a modern UI using Tailwind CSS.

## Features

- User authentication (Signup and Login)
- PostgreSQL database integration
- Modern UI with Tailwind CSS
- Form validation and error handling
- Secure password hashing
- Session management

## Setup Instructions

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file in the root directory with the following variables:
   ```
   FLASK_APP=app.py
   FLASK_ENV=development
   SECRET_KEY=your-secret-key
   DATABASE_URL=postgresql://username:password@localhost:5432/genix_db
   ```
5. Initialize the database:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```
6. Run the application:
   ```bash
   flask run
   ```

## Project Structure

```
.
├── app.py              # Flask application
├── config.py           # Configuration settings
├── models.py           # Database models
├── requirements.txt    # Project dependencies
├── static/            # Static files (CSS, JS, images)
├── templates/         # Jinja2 templates
└── .env              # Environment variables
```

## Development

- Frontend: Tailwind CSS
- Backend: Flask (Python)
- Database: PostgreSQL
- Template Engine: Jinja2

## Deployment

The application can be deployed on Render or Vercel/Netlify. See deployment documentation for specific instructions. #   G e n i x _ h o m e  
 