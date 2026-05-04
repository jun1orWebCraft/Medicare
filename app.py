from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import mysql.connector
from mysql.connector import Error
from functools import wraps
from datetime import datetime
import re
from security import hash_password, verify_password, encrypt_record_data, decrypt_record_data

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production-2024'

# Database configuration
db_config = {
    'host': 'localhost',
    'database': 'hospital_management',
    'user': 'root',
    'password': '',  
    'charset': 'utf8mb4'
}

def get_db_connection():
    """Create database connection"""
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None

# Decorators for access control
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if session.get('role') != role and session.get('role') != 'admin':
                return "Access denied", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_action(user_id, action, ip_address=None):
    """Log user actions"""
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
                (user_id, action, ip_address)
            )
            conn.commit()
        except Error as e:
            print(f"Log error: {e}")
        finally:
            cursor.close()
            conn.close()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_redirect():
    return render_template('login_redirect.html')

@app.route('/login/admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'admin'", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['role'] = user['role']
                session['email'] = user['email']
                log_action(user['id'], 'Admin login')
                return redirect(url_for('admin_dashboard'))
            else:
                return render_template('login_admin.html', error='Invalid credentials')
    return render_template('login_admin.html')

@app.route('/login/doctor', methods=['GET', 'POST'])
def login_doctor():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'doctor'", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['role'] = user['role']
                session['email'] = user['email']
                log_action(user['id'], 'Doctor login')
                return redirect(url_for('doctor_dashboard'))
            else:
                return render_template('login_doctor.html', error='Invalid credentials')
    return render_template('login_doctor.html')

@app.route('/login/patient', methods=['GET', 'POST'])
def login_patient():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'patient'", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['role'] = user['role']
                session['email'] = user['email']
                log_action(user['id'], 'Patient login')
                return redirect(url_for('patient_dashboard'))
            else:
                return render_template('login_patient.html', error='Invalid credentials')
    return render_template('login_patient.html')

@app.route('/login/assistant', methods=['GET', 'POST'])
def login_assistant():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s AND role = 'assistant'", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user and verify_password(password, user['password_hash']):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['role'] = user['role']
                session['email'] = user['email']
                log_action(user['id'], 'Assistant login')
                return redirect(url_for('assistant_dashboard'))
            else:
                return render_template('login_assistant.html', error='Invalid credentials')
    return render_template('login_assistant.html')

@app.route('/register/patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        age = request.form.get('age')
        gender = request.form.get('gender')
        address = request.form.get('address')
        phone = request.form.get('phone')
        
        if password != confirm_password:
            return render_template('register_patient.html', error='Passwords do not match')
        
        if len(password) < 8:
            return render_template('register_patient.html', error='Password must be at least 8 characters')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                # Check if email exists
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    return render_template('register_patient.html', error='Email already exists')
                
                # Insert user
                password_hash = hash_password(password)
                cursor.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'patient')",
                    (name, email, password_hash)
                )
                user_id = cursor.lastrowid
                
                # Insert patient details
                cursor.execute(
                    "INSERT INTO patients (user_id, age, gender, address, phone) VALUES (%s, %s, %s, %s, %s)",
                    (user_id, age, gender, address, phone)
                )
                
                conn.commit()
                log_action(user_id, 'Patient registered')
                return redirect(url_for('login_patient'))
            except Error as e:
                conn.rollback()
                return render_template('register_patient.html', error=f'Registration failed: {e}')
            finally:
                cursor.close()
                conn.close()
    
    return render_template('register_patient.html')

@app.route('/register/doctor', methods=['GET', 'POST'])
def register_doctor():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        specialization = request.form.get('specialization')
        qualification = request.form.get('qualification')
        experience = request.form.get('experience')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    return render_template('register_doctor.html', error='Email already exists')
                
                password_hash = hash_password(password)
                cursor.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'doctor')",
                    (name, email, password_hash)
                )
                user_id = cursor.lastrowid
                
                cursor.execute(
                    "INSERT INTO doctors (user_id, specialization, qualification, experience_years) VALUES (%s, %s, %s, %s)",
                    (user_id, specialization, qualification, experience)
                )
                
                conn.commit()
                log_action(session['user_id'], f'Added doctor: {email}')
                return redirect(url_for('admin_dashboard'))
            except Error as e:
                conn.rollback()
                return render_template('register_doctor.html', error=f'Registration failed: {e}')
            finally:
                cursor.close()
                conn.close()
    
    return render_template('register_doctor.html')

@app.route('/register/assistant', methods=['GET', 'POST'])
def register_assistant():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
                if cursor.fetchone():
                    return render_template('register_assistant.html', error='Email already exists')
                
                password_hash = hash_password(password)
                cursor.execute(
                    "INSERT INTO users (name, email, password_hash, role) VALUES (%s, %s, %s, 'assistant')",
                    (name, email, password_hash)
                )
                
                conn.commit()
                log_action(session['user_id'], f'Added assistant: {email}')
                return redirect(url_for('admin_dashboard'))
            except Error as e:
                conn.rollback()
                return render_template('register_assistant.html', error=f'Registration failed: {e}')
            finally:
                cursor.close()
                conn.close()
    
    return render_template('register_assistant.html')

# Admin Dashboard Routes
@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    conn = get_db_connection()
    stats = {}
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT COUNT(*) as total FROM users")
        stats['total_users'] = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'doctor'")
        stats['total_doctors'] = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as total FROM users WHERE role = 'patient'")
        stats['total_patients'] = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as total FROM appointments")
        stats['total_appointments'] = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as total FROM records")
        stats['total_records'] = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(*) as total FROM logs")
        stats['total_logs'] = cursor.fetchone()['total']
        
        cursor.close()
        conn.close()
    
    return render_template('admin_dashboard.html', stats=stats, user_name=session['user_name'])

@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    conn = get_db_connection()
    users = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC")
        users = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/remove/<int:user_id>')
@login_required
@role_required('admin')
def remove_user(user_id):
    if user_id == session['user_id']:
        return "Cannot remove yourself", 400
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            log_action(session['user_id'], f'Removed user ID: {user_id}')
        except Error as e:
            conn.rollback()
        finally:
            cursor.close()
            conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/logs')
@login_required
@role_required('admin')
def admin_logs():
    conn = get_db_connection()
    logs = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT l.*, u.name, u.email 
            FROM logs l 
            JOIN users u ON l.user_id = u.id 
            ORDER BY l.timestamp DESC 
            LIMIT 100
        """)
        logs = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('admin_logs.html', logs=logs)

# Doctor Dashboard Routes
@app.route('/doctor/dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    conn = get_db_connection()
    doctor_id = None
    stats = {}
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM doctors WHERE user_id = %s", (session['user_id'],))
        doctor = cursor.fetchone()
        if doctor:
            doctor_id = doctor['id']
            
            cursor.execute("""
                SELECT COUNT(DISTINCT patient_id) as patients 
                FROM records WHERE doctor_id = %s
            """, (doctor_id,))
            stats['total_patients'] = cursor.fetchone()['patients']
            
            cursor.execute("""
                SELECT COUNT(*) as appointments 
                FROM appointments WHERE doctor_id = %s
            """, (doctor_id,))
            stats['total_appointments'] = cursor.fetchone()['appointments']
            
            cursor.execute("""
                SELECT COUNT(*) as records 
                FROM records WHERE doctor_id = %s
            """, (doctor_id,))
            stats['total_records'] = cursor.fetchone()['records']
        
        cursor.close()
        conn.close()
    
    return render_template('doctor_dashboard.html', stats=stats, user_name=session['user_name'])

@app.route('/doctor/patients')
@login_required
@role_required('doctor')
def doctor_patients():
    conn = get_db_connection()
    patients = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT DISTINCT p.*, u.name, u.email 
            FROM patients p 
            JOIN users u ON p.user_id = u.id 
            JOIN records r ON p.id = r.patient_id 
            JOIN doctors d ON r.doctor_id = d.id 
            WHERE d.user_id = %s
        """, (session['user_id'],))
        patients = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('doctor_patients.html', patients=patients)

@app.route('/doctor/records/<int:patient_id>')
@login_required
@role_required('doctor')
def doctor_records(patient_id):
    conn = get_db_connection()
    records = []
    patient_info = None
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        # Get patient info
        cursor.execute("""
            SELECT p.*, u.name 
            FROM patients p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = %s
        """, (patient_id,))
        patient_info = cursor.fetchone()
        
        # Get records
        cursor.execute("""
            SELECT r.*, u.name as doctor_name 
            FROM records r 
            JOIN doctors d ON r.doctor_id = d.id 
            JOIN users u ON d.user_id = u.id 
            WHERE r.patient_id = %s
            ORDER BY r.created_at DESC
        """, (patient_id,))
        records_raw = cursor.fetchall()
        
        # Decrypt records
        for record in records_raw:
            decrypted = decrypt_record_data(record['encrypted_data'])
            record['diagnosis'] = decrypted.get('diagnosis', '')
            record['prescription'] = decrypted.get('prescription', '')
            record['notes'] = decrypted.get('notes', '')
        
        records = records_raw
        cursor.close()
        conn.close()
    
    return render_template('doctor_records.html', records=records, patient_info=patient_info)

@app.route('/doctor/records/add/<int:patient_id>', methods=['POST'])
@login_required
@role_required('doctor')
def add_record(patient_id):
    diagnosis = request.form.get('diagnosis')
    prescription = request.form.get('prescription')
    notes = request.form.get('notes')
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM doctors WHERE user_id = %s", (session['user_id'],))
            doctor = cursor.fetchone()
            doctor_id = doctor[0]
            
            encrypted = encrypt_record_data(diagnosis, prescription, notes)
            cursor.execute(
                "INSERT INTO records (patient_id, doctor_id, encrypted_data) VALUES (%s, %s, %s)",
                (patient_id, doctor_id, encrypted)
            )
            conn.commit()
            log_action(session['user_id'], f'Added medical record for patient {patient_id}')
        except Error as e:
            conn.rollback()
            print(f"Error adding record: {e}")
        finally:
            cursor.close()
            conn.close()
    
    return redirect(url_for('doctor_records', patient_id=patient_id))

@app.route('/doctor/appointments')
@login_required
@role_required('doctor')
def doctor_appointments():
    conn = get_db_connection()
    appointments = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT a.*, p.id as patient_id, u.name as patient_name, p.phone 
            FROM appointments a 
            JOIN patients p ON a.patient_id = p.id 
            JOIN users u ON p.user_id = u.id 
            JOIN doctors d ON a.doctor_id = d.id 
            WHERE d.user_id = %s 
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """, (session['user_id'],))
        appointments = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('doctor_appointments.html', appointments=appointments)

@app.route('/doctor/appointments/update/<int:appointment_id>/<string:status>')
@login_required
@role_required('doctor')
def update_appointment_status(appointment_id, status):
    if status not in ['approved', 'rejected', 'completed']:
        return "Invalid status", 400
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE appointments SET status = %s WHERE id = %s",
                (status, appointment_id)
            )
            conn.commit()
            log_action(session['user_id'], f'Updated appointment {appointment_id} to {status}')
        except Error as e:
            conn.rollback()
        finally:
            cursor.close()
            conn.close()
    
    return redirect(url_for('doctor_appointments'))

# Patient Dashboard Routes
@app.route('/patient/dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    conn = get_db_connection()
    patient_id = None
    stats = {}
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM patients WHERE user_id = %s", (session['user_id'],))
        patient = cursor.fetchone()
        if patient:
            patient_id = patient['id']
            
            cursor.execute("SELECT COUNT(*) as records FROM records WHERE patient_id = %s", (patient_id,))
            stats['total_records'] = cursor.fetchone()['records']
            
            cursor.execute("SELECT COUNT(*) as appointments FROM appointments WHERE patient_id = %s", (patient_id,))
            stats['total_appointments'] = cursor.fetchone()['appointments']
            
            cursor.execute(
                "SELECT COUNT(*) as pending FROM appointments WHERE patient_id = %s AND status = 'pending'",
                (patient_id,)
            )
            stats['pending_appointments'] = cursor.fetchone()['pending']
        
        cursor.close()
        conn.close()
    
    return render_template('patient_dashboard.html', stats=stats, user_name=session['user_name'])

@app.route('/patient/records')
@login_required
@role_required('patient')
def patient_records():
    conn = get_db_connection()
    records = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT r.*, u.name as doctor_name, d.specialization
            FROM records r 
            JOIN doctors d ON r.doctor_id = d.id 
            JOIN users u ON d.user_id = u.id 
            JOIN patients p ON r.patient_id = p.id 
            WHERE p.user_id = %s
            ORDER BY r.created_at DESC
        """, (session['user_id'],))
        records_raw = cursor.fetchall()
        
        for record in records_raw:
            decrypted = decrypt_record_data(record['encrypted_data'])
            record['diagnosis'] = decrypted.get('diagnosis', '')
            record['prescription'] = decrypted.get('prescription', '')
            record['notes'] = decrypted.get('notes', '')
        
        records = records_raw
        cursor.close()
        conn.close()
    
    return render_template('patient_records.html', records=records)

@app.route('/patient/appointments')
@login_required
@role_required('patient')
def patient_appointments():
    conn = get_db_connection()
    appointments = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT a.*, u.name as doctor_name, d.specialization
            FROM appointments a 
            JOIN doctors d ON a.doctor_id = d.id 
            JOIN users u ON d.user_id = u.id 
            JOIN patients p ON a.patient_id = p.id 
            WHERE p.user_id = %s
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """, (session['user_id'],))
        appointments = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('patient_appointments.html', appointments=appointments)

@app.route('/patient/appointments/book', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def book_appointment():
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        appointment_date = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason')
        
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id FROM patients WHERE user_id = %s", (session['user_id'],))
                patient = cursor.fetchone()
                patient_id = patient[0]
                
                cursor.execute(
                    "INSERT INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, reason) VALUES (%s, %s, %s, %s, %s)",
                    (patient_id, doctor_id, appointment_date, appointment_time, reason)
                )
                conn.commit()
                log_action(session['user_id'], f'Booked appointment with doctor {doctor_id}')
                return redirect(url_for('patient_appointments'))
            except Error as e:
                conn.rollback()
                return render_template('book_appointment.html', error=f'Booking failed: {e}')
            finally:
                cursor.close()
                conn.close()
    
    conn = get_db_connection()
    doctors = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT d.id, u.name, d.specialization 
            FROM doctors d 
            JOIN users u ON d.user_id = u.id
        """)
        doctors = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('book_appointment.html', doctors=doctors)

# Assistant Dashboard Routes
@app.route('/assistant/dashboard')
@login_required
@role_required('assistant')
def assistant_dashboard():
    conn = get_db_connection()
    stats = {}
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as patients FROM patients")
        stats['total_patients'] = cursor.fetchone()['patients']
        
        cursor.execute("SELECT COUNT(*) as appointments FROM appointments")
        stats['total_appointments'] = cursor.fetchone()['appointments']
        
        cursor.execute("SELECT COUNT(*) as pending FROM appointments WHERE status = 'pending'")
        stats['pending_appointments'] = cursor.fetchone()['pending']
        
        cursor.execute("SELECT COUNT(*) as records FROM records")
        stats['total_records'] = cursor.fetchone()['records']
        
        cursor.close()
        conn.close()
    
    return render_template('assistant_dashboard.html', stats=stats, user_name=session['user_name'])

@app.route('/assistant/patients')
@login_required
@role_required('assistant')
def assistant_patients():
    conn = get_db_connection()
    patients = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT p.*, u.name, u.email, u.created_at 
            FROM patients p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY u.name
        """)
        patients = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('assistant_patients.html', patients=patients)

@app.route('/assistant/records/<int:patient_id>')
@login_required
@role_required('assistant')
def assistant_records(patient_id):
    conn = get_db_connection()
    records = []
    patient_info = None
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT p.*, u.name 
            FROM patients p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = %s
        """, (patient_id,))
        patient_info = cursor.fetchone()
        
        cursor.execute("""
            SELECT r.*, u.name as doctor_name, d.specialization 
            FROM records r 
            JOIN doctors d ON r.doctor_id = d.id 
            JOIN users u ON d.user_id = u.id 
            WHERE r.patient_id = %s
            ORDER BY r.created_at DESC
        """, (patient_id,))
        records_raw = cursor.fetchall()
        
        for record in records_raw:
            decrypted = decrypt_record_data(record['encrypted_data'])
            record['diagnosis'] = decrypted.get('diagnosis', '')
            record['prescription'] = decrypted.get('prescription', '')
            record['notes'] = decrypted.get('notes', '')
        
        records = records_raw
        cursor.close()
        conn.close()
    
    return render_template('assistant_records.html', records=records, patient_info=patient_info)

@app.route('/assistant/records/print/<int:record_id>')
@login_required
@role_required('assistant')
def print_record(record_id):
    conn = get_db_connection()
    record = None
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT r.*, u.name as doctor_name, d.specialization, 
                   p2.name as patient_name, p.age, p.gender, p.address, p.phone
            FROM records r 
            JOIN doctors d ON r.doctor_id = d.id 
            JOIN users u ON d.user_id = u.id 
            JOIN patients p ON r.patient_id = p.id
            JOIN users p2 ON p.user_id = p2.id
            WHERE r.id = %s
        """, (record_id,))
        record = cursor.fetchone()
        
        if record:
            decrypted = decrypt_record_data(record['encrypted_data'])
            record['diagnosis'] = decrypted.get('diagnosis', '')
            record['prescription'] = decrypted.get('prescription', '')
            record['notes'] = decrypted.get('notes', '')
        
        cursor.close()
        conn.close()
    
    return render_template('print_record.html', record=record)

@app.route('/assistant/appointments')
@login_required
@role_required('assistant')
def assistant_appointments():
    conn = get_db_connection()
    appointments = []
    
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT a.*, p.id as patient_id, u.name as patient_name, 
                   d2.name as doctor_name, do.specialization
            FROM appointments a 
            JOIN patients p ON a.patient_id = p.id 
            JOIN users u ON p.user_id = u.id 
            JOIN doctors d ON a.doctor_id = d.id
            JOIN users d2 ON d.user_id = d2.id
            LEFT JOIN doctors do ON d.id = do.id
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """)
        appointments = cursor.fetchall()
        cursor.close()
        conn.close()
    
    return render_template('assistant_appointments.html', appointments=appointments)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'Logout')
    session.clear()
    return redirect(url_for('index'))

# Add this function to app.py to make now() available in templates
@app.context_processor
def utility_processor():
    from datetime import datetime
    return dict(now=datetime.now)

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)