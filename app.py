from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from pymongo import MongoClient
from datetime import datetime, timedelta
import json
import os
from config import MONGO_URI

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use environment variable for production

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client['REQUESTS']
collection = db['users']

# Admin credentials (you can change these)
ADMIN_USERNAME = "technoelite@nec"
ADMIN_PASSWORD = "technoelite@2025"

@app.route('/')
def index():
    return render_template('form.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(f):
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/submit', methods=['POST'])
def submit():
    try:
        rollno = request.form['rollno']
        branch = request.form['branch']
        reason = request.form['reason']
        email = request.form['email']
        permission = {
            'rollno': rollno,
            'branch': branch,
            'reason': reason,
            'email': email,
            'submitted_at': datetime.now()
        }
        collection.insert_one(permission)
        return jsonify({'success': True, 'message': 'Permission submitted successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/dashboard')
@login_required
def dashboard():
    # Get query parameters for filtering
    rollno_filter = request.args.get('rollno', '')
    date_filter = request.args.get('date', '')
    
    # Build query
    query = {}
    if rollno_filter:
        query['rollno'] = {'$regex': rollno_filter, '$options': 'i'}
    if date_filter:
        # Convert date string to datetime range
        start_date = datetime.strptime(date_filter, '%Y-%m-%d')
        end_date = start_date + timedelta(days=1)
        query['submitted_at'] = {'$gte': start_date, '$lt': end_date}
    
    # Get permissions from MongoDB with sorting by date in decreasing order
    permissions = list(collection.find(query).sort('submitted_at', -1))
    
    # Convert ObjectId to string for JSON serialization
    for permission in permissions:
        permission['_id'] = str(permission['_id'])
        if 'submitted_at' in permission:
            # Check if submitted_at is already a string or needs conversion
            if hasattr(permission['submitted_at'], 'isoformat'):
                # Format as DD/MM/YYYY HH:MM:SS
                permission['submitted_at'] = permission['submitted_at'].strftime('%d/%m/%Y %H:%M:%S')
            elif isinstance(permission['submitted_at'], str):
                try:
                    dt = datetime.fromisoformat(permission['submitted_at'].replace('Z', '+00:00'))
                    permission['submitted_at'] = dt.strftime('%d/%m/%Y %H:%M:%S')
                except:
                    pass
    
    # Calculate today's, this month's, and total requests
    today = datetime.now().date()
    this_month = today.month
    this_year = today.year
    todays_requests = 0
    this_month_requests = 0
    for permission in permissions:
        dt = None
        if 'submitted_at' in permission:
            try:
                dt = datetime.strptime(permission['submitted_at'], '%d/%m/%Y %H:%M:%S')
            except Exception:
                pass
        if dt:
            if dt.date() == today:
                todays_requests += 1
            if dt.month == this_month and dt.year == this_year:
                this_month_requests += 1
    total_requests = len(permissions)
    return render_template('dashboard.html', permissions=permissions, 
                         rollno_filter=rollno_filter, date_filter=date_filter, today_date=today.strftime('%Y-%m-%d'),
                         todays_requests=todays_requests, this_month_requests=this_month_requests, total_requests=total_requests)

@app.route('/analytics')
@login_required
def analytics():
    # Get all permissions
    permissions = list(collection.find())
    today = datetime.now().date()
    this_month = today.month
    this_year = today.year
    week_ago = datetime.now() - timedelta(days=7)
    todays_requests = 0
    this_month_requests = 0
    this_week_requests = 0
    branch_counts = {}
    for permission in permissions:
        dt = None
        if 'submitted_at' in permission:
            try:
                if hasattr(permission['submitted_at'], 'isoformat'):
                    # It's a datetime object
                    dt = permission['submitted_at']
                elif isinstance(permission['submitted_at'], str):
                    # Try to parse the string format
                    if '/' in permission['submitted_at']:
                        # DD/MM/YYYY HH:MM:SS format
                        dt = datetime.strptime(permission['submitted_at'], '%d/%m/%Y %H:%M:%S')
                    else:
                        # Try ISO format
                        dt = datetime.fromisoformat(permission['submitted_at'].replace('Z', '+00:00'))
            except Exception as e:
                print(f"Date parsing error: {e} for {permission['submitted_at']}")
                pass
        if dt:
            if dt.date() == today:
                todays_requests += 1
            if dt.month == this_month and dt.year == this_year:
                this_month_requests += 1
            if dt >= week_ago:
                this_week_requests += 1
        # Branch stats
        branch = permission.get('branch', 'Unknown')
        branch_counts[branch] = branch_counts.get(branch, 0) + 1
    total_permissions = len(permissions)
    analytics_data = {
        'total_permissions': total_permissions,
        'todays_requests': todays_requests,
        'this_month_requests': this_month_requests,
        'this_week_requests': this_week_requests,
        'branch_stats': branch_counts,
        'recent_permissions': permissions[:10]  # last 10 for recent activity
    }
    # Ensure all submitted_at fields are strings for recent_permissions
    for p in permissions:
        if 'submitted_at' in p and hasattr(p['submitted_at'], 'isoformat'):
            p['submitted_at'] = p['submitted_at'].strftime('%d/%m/%Y %H:%M:%S')
        elif 'submitted_at' in p and not isinstance(p['submitted_at'], str):
            try:
                p['submitted_at'] = str(p['submitted_at'])
            except:
                p['submitted_at'] = ''
    return render_template('analytics.html', analytics=analytics_data)

@app.route('/export')
@login_required
def export_csv():
    # Get all permissions
    permissions = list(collection.find())
    # Create CSV data
    csv_data = []
    for permission in permissions:
        # Format the submitted_at date properly
        submitted_at = permission.get('submitted_at', '')
        if submitted_at:
            if hasattr(submitted_at, 'strftime'):
                # If it's a datetime object
                formatted_date = submitted_at.strftime('%d/%m/%Y %H:%M:%S')
            elif isinstance(submitted_at, str):
                # If it's already a string, use as is
                formatted_date = submitted_at
            else:
                formatted_date = str(submitted_at)
        else:
            formatted_date = ''
            
        csv_data.append({
            'Roll Number': permission.get('rollno', ''),
            'Email': permission.get('email', ''),
            'Branch': permission.get('branch', ''),
            'Reason': permission.get('reason', ''),
            'Submitted At': formatted_date
        })
    return jsonify(csv_data)

@app.route('/clear-data')
@login_required
def clear_data():
    try:
        # Clear all data from MongoDB
        collection.delete_many({})
        return jsonify({'success': True, 'message': 'All data cleared successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/student-history/<rollno>')
@login_required
def get_student_history_api(rollno):
    # Get student's permission history
    history = list(collection.find({'rollno': rollno}).sort('submitted_at', -1))
    # Convert ObjectId to string
    for record in history:
        record['_id'] = str(record['_id'])
        if 'submitted_at' in record:
            if hasattr(record['submitted_at'], 'isoformat'):
                record['submitted_at'] = record['submitted_at'].strftime('%d/%m/%Y %H:%M:%S')
            elif isinstance(record['submitted_at'], str):
                try:
                    dt = datetime.fromisoformat(record['submitted_at'].replace('Z', '+00:00'))
                    record['submitted_at'] = dt.strftime('%d/%m/%Y %H:%M:%S')
                except:
                    pass
    return jsonify(history)

@app.route('/api/analytics')
@login_required
def get_analytics_api():
    # Get all permissions
    permissions = list(collection.find())
    today = datetime.now().date()
    this_month = today.month
    this_year = today.year
    week_ago = datetime.now() - timedelta(days=7)
    
    # Calculate statistics
    todays_requests = 0
    this_month_requests = 0
    this_week_requests = 0
    branch_counts = {}
    time_counts = {'9AM': 0, '12PM': 0, '3PM': 0, '6PM': 0}
    daily_counts = {'Mon': 0, 'Tue': 0, 'Wed': 0, 'Thu': 0, 'Fri': 0, 'Sat': 0, 'Sun': 0}
    
    # Initialize monthly counts for all months
    monthly_counts = {
        'January': 0, 'February': 0, 'March': 0, 'April': 0, 'May': 0, 'June': 0,
        'July': 0, 'August': 0, 'September': 0, 'October': 0, 'November': 0, 'December': 0
    }
    
    for permission in permissions:
        dt = None
        if 'submitted_at' in permission:
            try:
                if hasattr(permission['submitted_at'], 'isoformat'):
                    # It's a datetime object
                    dt = permission['submitted_at']
                elif isinstance(permission['submitted_at'], str):
                    # Try to parse the string format
                    if '/' in permission['submitted_at']:
                        # DD/MM/YYYY HH:MM:SS format
                        dt = datetime.strptime(permission['submitted_at'], '%d/%m/%Y %H:%M:%S')
                    else:
                        # Try ISO format
                        dt = datetime.fromisoformat(permission['submitted_at'].replace('Z', '+00:00'))
            except Exception as e:
                print(f"Date parsing error: {e} for {permission['submitted_at']}")
                pass
        
        if dt:
            # Today's requests
            if dt.date() == today:
                todays_requests += 1
            
            # This month's requests
            if dt.month == this_month and dt.year == this_year:
                this_month_requests += 1
            
            # This week's requests
            if dt >= week_ago:
                this_week_requests += 1
            
            # Daily trend (last 7 days)
            days_ago = (today - dt.date()).days
            if days_ago < 7:
                day_name = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][dt.weekday()]
                daily_counts[day_name] += 1
            
            # Monthly analysis (all years) - ensure proper month calculation
            month_names = ['January', 'February', 'March', 'April', 'May', 'June',
                          'July', 'August', 'September', 'October', 'November', 'December']
            if 1 <= dt.month <= 12:  # Ensure valid month
                month_name = month_names[dt.month - 1]
                monthly_counts[month_name] += 1
            
            # Time distribution
            hour = dt.hour
            if 9 <= hour < 12:
                time_counts['9AM'] += 1
            elif 12 <= hour < 15:
                time_counts['12PM'] += 1
            elif 15 <= hour < 18:
                time_counts['3PM'] += 1
            elif 18 <= hour < 21:
                time_counts['6PM'] += 1
        
        # Branch stats
        branch = permission.get('branch', 'Unknown')
        branch_counts[branch] = branch_counts.get(branch, 0) + 1
    
    total_permissions = len(permissions)
    
    analytics_data = {
        'total_permissions': total_permissions,
        'todays_requests': todays_requests,
        'this_month_requests': this_month_requests,
        'this_week_requests': this_week_requests,
        'branch_stats': branch_counts,
        'time_distribution': time_counts,
        'daily_trend': daily_counts,
        'monthly_analysis': monthly_counts,
        'recent_permissions': []
    }
    
    # Get recent permissions (last 10)
    recent_permissions = list(collection.find().sort('submitted_at', -1).limit(10))
    for p in recent_permissions:
        p['_id'] = str(p['_id'])
        if 'submitted_at' in p and hasattr(p['submitted_at'], 'isoformat'):
            p['submitted_at'] = p['submitted_at'].strftime('%d/%m/%Y %H:%M:%S')
        analytics_data['recent_permissions'].append(p)
    
    return jsonify(analytics_data)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
