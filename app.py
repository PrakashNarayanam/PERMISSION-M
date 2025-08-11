from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from pymongo import MongoClient
from datetime import datetime, timedelta, timezone
try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except Exception:
    ZoneInfo = None
import json
import os
from config import MONGO_URI

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client['REQUESTS']
collection = db['users']

# Timezone for IST (fallback if zoneinfo db missing)
try:
    IST = ZoneInfo('Asia/Kolkata') if ZoneInfo else timezone(timedelta(hours=5, minutes=30))
except Exception:
    IST = timezone(timedelta(hours=5, minutes=30))

def to_ist_datetime(dt_value):
    """Convert various stored date formats to timezone-aware IST datetime.
    - If datetime has tzinfo, convert to IST
    - If naive datetime, assume UTC then convert to IST
    - If string in DD/MM/YYYY HH:MM:SS, assume IST
    - If ISO string, parse, assume UTC if naive, then convert to IST
    Returns datetime or None
    """
    dt = None
    try:
        if hasattr(dt_value, 'isoformat'):
            # datetime object
            if dt_value.tzinfo is None:
                dt = dt_value.replace(tzinfo=timezone.utc).astimezone(IST)
            else:
                dt = dt_value.astimezone(IST)
        elif isinstance(dt_value, str):
            if '/' in dt_value:
                # DD/MM/YYYY HH:MM:SS presumed IST already
                dt = datetime.strptime(dt_value, '%d/%m/%Y %H:%M:%S').replace(tzinfo=IST)
            else:
                # ISO-like format string (e.g., YYYY-MM-DD HH:MM:SS)
                parsed = datetime.fromisoformat(dt_value.replace('Z', '+00:00'))
                # If no timezone info present, assume it was recorded in IST
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=IST)
                dt = parsed.astimezone(IST)
    except Exception:
        dt = None
    return dt

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
            # Store in UTC for consistency
            'submitted_at': datetime.now(timezone.utc)
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
    
    # Build query with support for both datetime and string-stored dates
    and_conditions = []
    if rollno_filter:
        and_conditions.append({'rollno': {'$regex': rollno_filter, '$options': 'i'}})
    if date_filter:
        # Convert selected date (assumed IST) to UTC range and also match string-stored timestamps
        ist_start = datetime.strptime(date_filter, '%Y-%m-%d').replace(tzinfo=IST)
        ist_end = ist_start + timedelta(days=1)
        utc_start = ist_start.astimezone(timezone.utc).replace(tzinfo=None)
        utc_end = ist_end.astimezone(timezone.utc).replace(tzinfo=None)
        dd = ist_start.day
        mm = ist_start.month
        yyyy = ist_start.year
        ddmmyyyy_fixed = ist_start.strftime('%d/%m/%Y')
        ymd_fixed = ist_start.strftime('%Y-%m-%d')
        ddmmyyyy_opt = f'^0?{dd}/0?{mm}/{yyyy}\\b'
        ymd_opt = f'^{yyyy}-0?{mm}-0?{dd}\\b'
        and_conditions.append({'$or': [
            {'submitted_at': {'$gte': utc_start, '$lt': utc_end}},
            {'submitted_at': {'$regex': f'^{ddmmyyyy_fixed}\\b'}},
            {'submitted_at': {'$regex': f'^{ymd_fixed}\\b'}},
            {'submitted_at': {'$regex': ddmmyyyy_opt}},
            {'submitted_at': {'$regex': ymd_opt}}
        ]})
    query = {'$and': and_conditions} if and_conditions else {}
    
    # Get permissions from MongoDB with sorting by date in decreasing order
    permissions = list(collection.find(query).sort('submitted_at', -1))

    # Robust server-side filter by selected date in IST (covers mixed storage formats)
    if date_filter:
        ist_target = datetime.strptime(date_filter, '%Y-%m-%d').date()
        ddmmyyyy = datetime.strptime(date_filter, '%Y-%m-%d').strftime('%d/%m/%Y')
        ymd = date_filter
        filtered = []
        for p in permissions:
            dt_ist = to_ist_datetime(p.get('submitted_at'))
            if dt_ist and dt_ist.date() == ist_target:
                filtered.append(p)
                continue
            s = p.get('submitted_at')
            if isinstance(s, str) and (s.startswith(ddmmyyyy) or s.startswith(ymd)):
                filtered.append(p)
        permissions = filtered

    # Calculate today's, this month's, and total requests; also format submitted_at as IST string
    today = datetime.now(IST).date()
    this_month = today.month
    this_year = today.year
    todays_requests = 0
    this_month_requests = 0
    for permission in permissions:
        permission['_id'] = str(permission['_id'])
        ist_dt = to_ist_datetime(permission.get('submitted_at'))
        if ist_dt:
            if ist_dt.date() == today:
                todays_requests += 1
            if ist_dt.month == this_month and ist_dt.year == this_year:
                this_month_requests += 1
            permission['submitted_at'] = ist_dt.strftime('%d/%m/%Y %I:%M:%S %p')
    total_requests = len(permissions)
    return render_template('dashboard.html', permissions=permissions, 
                         rollno_filter=rollno_filter, date_filter=date_filter, today_date=today.strftime('%Y-%m-%d'),
                         todays_requests=todays_requests, this_month_requests=this_month_requests, total_requests=total_requests)

@app.route('/analytics')
@login_required
def analytics():
    # Get all permissions
    permissions = list(collection.find())
    today = datetime.now(IST).date()
    this_month = today.month
    this_year = today.year
    # Week boundaries: Monday 00:00 IST to next Monday 00:00 IST
    now_ist = datetime.now(IST)
    start_of_week = (now_ist - timedelta(days=now_ist.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_next_week = start_of_week + timedelta(days=7)
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
            dt_ist = to_ist_datetime(dt)
            if dt_ist and dt_ist.date() == today:
                todays_requests += 1
            if dt_ist and dt_ist.month == this_month and dt_ist.year == this_year:
                this_month_requests += 1
            if dt_ist and (start_of_week <= dt_ist < start_of_next_week):
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
        if 'submitted_at' in p:
            ist_dt = to_ist_datetime(p['submitted_at'])
            if ist_dt:
                p['submitted_at'] = ist_dt.strftime('%d/%m/%Y %I:%M:%S %p')
    return render_template('analytics.html', analytics=analytics_data)

@app.route('/export')
@login_required
def export_csv():
    # Optional filters to match dashboard
    rollno_filter = request.args.get('rollno', '')
    date_filter = request.args.get('date', '')

    and_conditions = []
    if rollno_filter:
        and_conditions.append({'rollno': {'$regex': rollno_filter, '$options': 'i'}})
    if date_filter:
        ist_start = datetime.strptime(date_filter, '%Y-%m-%d').replace(tzinfo=IST)
        ist_end = ist_start + timedelta(days=1)
        utc_start = ist_start.astimezone(timezone.utc).replace(tzinfo=None)
        utc_end = ist_end.astimezone(timezone.utc).replace(tzinfo=None)
        ddmmyyyy = ist_start.strftime('%d/%m/%Y')
        ymd = ist_start.strftime('%Y-%m-%d')
        and_conditions.append({'$or': [
            {'submitted_at': {'$gte': utc_start, '$lt': utc_end}},
            {'submitted_at': {'$regex': f'^{ddmmyyyy}\\b'}},
            {'submitted_at': {'$regex': f'^{ymd}\\b'}}
        ]})
    query = {'$and': and_conditions} if and_conditions else {}

    permissions = list(collection.find(query).sort('submitted_at', -1))

    # Build CSV text with IST and 12-hour format
    def gen_rows():
        yield 'Roll Number,Email,Branch,Reason,Date and Time\n'
        for p in permissions:
            ist_dt = to_ist_datetime(p.get('submitted_at'))
            date_str = ist_dt.strftime('%d/%m/%Y %I:%M:%S %p') if ist_dt else ''
            def esc(v):
                if v is None:
                    return ''
                s = str(v)
                if any(ch in s for ch in [',','"','\n','\r']):
                    return '"' + s.replace('"','""') + '"'
                return s
            yield f"{esc(p.get('rollno',''))},{esc(p.get('email',''))},{esc(p.get('branch',''))},{esc(p.get('reason',''))},{esc(date_str)}\n"

    csv_text = ''.join(list(gen_rows()))
    return Response(csv_text, mimetype='text/csv', headers={
        'Content-Disposition': f'attachment; filename=permissions_data_{datetime.now(IST).strftime('%Y-%m-%d')}.csv'
    })

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
            ist_dt = to_ist_datetime(record['submitted_at'])
            if ist_dt:
                record['submitted_at'] = ist_dt.strftime('%d/%m/%Y %I:%M:%S %p')
    return jsonify(history)

@app.route('/api/analytics')
@login_required
def get_analytics_api():
    # Get all permissions
    permissions = list(collection.find())
    today = datetime.now(IST).date()
    this_month = today.month
    this_year = today.year
    now_ist = datetime.now(IST)
    start_of_week = (now_ist - timedelta(days=now_ist.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_next_week = start_of_week + timedelta(days=7)
    
    # Calculate statistics
    todays_requests = 0
    this_month_requests = 0
    this_week_requests = 0
    branch_counts = {}
    # Hourly time distribution ranges with AM/PM
    time_labels = ['9-10 AM', '10-11 AM', '11 AM-12 PM', '12-1 PM', '1-2 PM', '2-3 PM', '3-4 PM']
    hour_to_label = {9: '9-10 AM', 10: '10-11 AM', 11: '11 AM-12 PM', 12: '12-1 PM', 13: '1-2 PM', 14: '2-3 PM', 15: '3-4 PM'}
    time_counts = {label: 0 for label in time_labels}
    # Daily trend for current week (Mon-Sun)
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
            dt_ist = to_ist_datetime(dt)
            # Today's requests
            if dt_ist and dt_ist.date() == today:
                todays_requests += 1
            
            # This month's requests
            if dt_ist and dt_ist.month == this_month and dt_ist.year == this_year:
                this_month_requests += 1
            
            # This week's requests (Mon-Sun)
            if dt_ist and (start_of_week <= dt_ist < start_of_next_week):
                this_week_requests += 1
            
            # Daily trend (current week Mon-Sun)
            if dt_ist and (start_of_week.date() <= dt_ist.date() <= (start_of_week + timedelta(days=6)).date()):
                day_name = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][dt_ist.weekday()]
                daily_counts[day_name] += 1
            
            # Monthly analysis (current year only)
            month_names = ['January', 'February', 'March', 'April', 'May', 'June',
                          'July', 'August', 'September', 'October', 'November', 'December']
            if dt_ist and dt_ist.year == this_year and 1 <= dt_ist.month <= 12:
                month_name = month_names[dt_ist.month - 1]
                monthly_counts[month_name] += 1
            
            # Time distribution hourly bucket in IST
            if dt_ist:
                hour = dt_ist.hour
                # Include 9:00-15:59 buckets; exclude 16:00 and later
                if 9 <= hour < 16 and hour in hour_to_label:
                    time_counts[hour_to_label[hour]] += 1
        
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
        if 'submitted_at' in p:
            ist_dt = to_ist_datetime(p['submitted_at'])
            if ist_dt:
                p['submitted_at'] = ist_dt.strftime('%d/%m/%Y %H:%M:%S')
        analytics_data['recent_permissions'].append(p)
    
    return jsonify(analytics_data)

# One-time admin utility to normalize stored timestamps to UTC datetimes
@app.route('/admin/normalize-timestamps', methods=['POST'])
@login_required
def normalize_timestamps():
    updated = 0
    scanned = 0
    errors = 0
    cursor = collection.find({}, {'submitted_at': 1})
    for doc in cursor:
        scanned += 1
        original = doc.get('submitted_at')
        if original is None:
            continue
        try:
            new_dt_utc = None
            if hasattr(original, 'isoformat'):
                # datetime object
                if original.tzinfo is None:
                    # Assume UTC
                    new_dt_utc = original.replace(tzinfo=timezone.utc)
                else:
                    new_dt_utc = original.astimezone(timezone.utc)
            elif isinstance(original, str):
                if '/' in original:
                    # DD/MM/YYYY HH:MM:SS stored as IST string
                    dt_ist = datetime.strptime(original, '%d/%m/%Y %H:%M:%S').replace(tzinfo=IST)
                    new_dt_utc = dt_ist.astimezone(timezone.utc)
                else:
                    parsed = datetime.fromisoformat(original.replace('Z', '+00:00'))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    new_dt_utc = parsed.astimezone(timezone.utc)
            if new_dt_utc is not None:
                collection.update_one({'_id': doc['_id']}, {'$set': {'submitted_at': new_dt_utc}})
                updated += 1
        except Exception:
            errors += 1
            continue
    return jsonify({'scanned': scanned, 'updated': updated, 'errors': errors})

# Admin endpoint to apply timestamp corrections by rollno/email
@app.route('/admin/apply-corrections', methods=['POST'])
@login_required
def apply_corrections():
    payload = request.get_json(silent=True, force=True)
    if not isinstance(payload, list):
        return jsonify({'success': False, 'message': 'Provide a JSON array of corrections'}), 400

    def parse_correction_ts(ts_str):
        if not ts_str or not isinstance(ts_str, str):
            return None
        formats = [
            '%Y-%m-%d %H:%M:%S',        # 2025-08-08 12:57:12
            '%d/%m/%Y %H:%M:%S',        # 08/08/2025 8:59:47 (24h assumed)
            '%d/%m/%Y %I:%M:%S %p',     # 08/08/2025 09:01:29 AM
        ]
        for fmt in formats:
            try:
                dt_local = datetime.strptime(ts_str.strip(), fmt).replace(tzinfo=IST)
                return dt_local
            except Exception:
                continue
        return None

    results = {'updated': 0, 'not_found': 0, 'invalid': 0, 'errors': 0}
    for item in payload:
        try:
            if not isinstance(item, dict):
                results['invalid'] += 1
                continue
            rollno = (item.get('rollno') or '').strip()
            email = (item.get('email') or '').strip()
            ts_str = item.get('submitted_at') or item.get('timestamp') or item.get('time')
            dt_ist = parse_correction_ts(ts_str)
            if not dt_ist or (not rollno and not email):
                results['invalid'] += 1
                continue
            dt_utc_naive = dt_ist.astimezone(timezone.utc).replace(tzinfo=None)
            # Build query by priority: both, then rollno, then email
            or_filters = []
            if rollno:
                or_filters.append({'rollno': rollno})
            if email:
                or_filters.append({'email': email})
            query = {'$or': or_filters} if len(or_filters) > 1 else (or_filters[0] if or_filters else {})
            doc = collection.find_one(query, sort=[('submitted_at', -1)])
            if not doc:
                results['not_found'] += 1
                continue
            collection.update_one({'_id': doc['_id']}, {'$set': {'submitted_at': dt_utc_naive}})
            results['updated'] += 1
        except Exception:
            results['errors'] += 1
            continue

    return jsonify({'success': True, **results})

if __name__ == '__main__':
    app.run(debug=True)
