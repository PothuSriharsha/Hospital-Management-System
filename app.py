from flask import Flask, render_template, request, redirect, session, flash, url_for
import mysql.connector
from functools import wraps
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
import string
import secrets
from datetime import datetime


app = Flask(__name__)
app.secret_key = 'harsha5454'

# MySQL Configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "harsha5454",
    "database": "hospital_db"
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# Authentication Decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def employee_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'employee':
            flash('Employee access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def patient_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'patient':
            flash('Patient access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated
@app.template_filter('dateformat')
def dateformat(value, format='%Y-%m-%d'):
    if isinstance(value, datetime):
        return value.strftime(format)
    return value


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        role = request.form.get('role', 'patient')

        conn = get_db_connection()
        if not conn:
            flash('Database connection error', 'danger')
            return render_template('login.html')

        try:
            cursor = conn.cursor(dictionary=True)
            table = 'patients' if role == 'patient' else 'medical_staff'
            cursor.execute(f"SELECT * FROM {table} WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and user.get('password') and check_password_hash(user['password'], password):
                session.clear()  # Clear any existing session
                session['logged_in'] = True
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['role'] = role
                session['name'] = user.get('name', '')

                # Store specific role for employees
                if role == 'employee':
                    session['employee_role'] = user.get('role', 'staff')  # Make sure your DB has this column

                flash('Login successful!', 'success')
                return redirect(url_for('home'))

            flash('Invalid email or password', 'danger')

        except mysql.connector.Error as err:
            flash(f'Database error: {err}', 'danger')
        finally:
            if 'cursor' in locals(): cursor.close()
            if conn: conn.close()

    return render_template('login.html')

@app.route('/employee/signup', methods=['GET', 'POST'])
def employee_signup():
    if request.method == 'POST':
        # Collect form data
        form_data = {
            'name': request.form.get('name', '').strip(),
            'email': request.form.get('email', '').strip().lower(),
            'password': request.form.get('password', ''),
            'contact': request.form.get('contact', '').strip(),
            'role': request.form.get('role', '').strip(),
            'department': request.form.get('department', '').strip(),
            'specialization': request.form.get('specialization', '').strip()
        }

        # Validate required fields
        errors = []
        if not form_data['name']: errors.append('Full name is required')
        if not form_data['email']: errors.append('Email is required')
        if not form_data['password']: errors.append('Password is required')
        if len(form_data['password']) < 8:
            errors.append('Password must be at least 8 characters')
        if not form_data['contact']: errors.append('Contact number is required')
        if not form_data['role']: errors.append('Role is required')

        # Validate role
        valid_roles = ['doctor', 'nurse', 'admin', 'receptionist']
        if form_data['role'] and form_data['role'] not in valid_roles:
            errors.append('Invalid role selected')

        if errors:
            for error in errors: flash(error, 'danger')
            return render_template('employee_signup.html', form_data=form_data)

        # Hash password
        hashed_password = generate_password_hash(form_data['password'])

        # Database operation
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'danger')
            return render_template('employee_signup.html', form_data=form_data)

        try:
            cursor = conn.cursor()

            # Check if email exists
            cursor.execute("SELECT id FROM medical_staff WHERE email = %s", (form_data['email'],))
            if cursor.fetchone():
                flash('This email is already registered. Please use a different email or login.', 'danger')
                return render_template('employee_signup.html', form_data=form_data)

            # Insert new employee
            cursor.execute("""
                INSERT INTO medical_staff
                (name, email, password, contact, role, department, specialization)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                form_data['name'],
                form_data['email'],
                hashed_password,
                form_data['contact'],
                form_data['role'],
                form_data['department'] if form_data['department'] else None,
                form_data['specialization'] if form_data['specialization'] else None
            ))

            conn.commit()
            flash('Registration successful! Please login with your new account.', 'success')
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            conn.rollback()
            flash(f'Registration failed due to a database error: {err}', 'danger')
            return render_template('employee_signup.html', form_data=form_data)
        finally:
            if 'cursor' in locals(): cursor.close()
            if conn: conn.close()

    return render_template('employee_signup.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Collect form data
        form_data = {
            'name': request.form.get('name', '').strip(),
            'email': request.form.get('email', '').strip().lower(),
            'password': request.form.get('password', ''),
            'age': request.form.get('age', '').strip(),
            'contact': request.form.get('contact', '').strip(),
            'address': request.form.get('address', '').strip(),
            'gender': request.form.get('gender', '').strip(),
            'dob': request.form.get('dob', '').strip()
        }

        # Validate required fields
        errors = []
        if not form_data['name']: errors.append('Full name is required')
        if not form_data['email']: errors.append('Email is required')
        if not form_data['password']: errors.append('Password is required')
        if len(form_data['password']) < 8:
            errors.append('Password must be at least 8 characters')
        if not form_data['age']: errors.append('Age is required')

        try:
            age = int(form_data['age'])
            if not (0 < age < 120): errors.append('Age must be between 1 and 120')
        except ValueError:
            errors.append('Age must be a valid number')

        if errors:
            for error in errors: flash(error, 'danger')
            return render_template('signup.html', form_data=form_data)

        # Hash password
        hashed_password = generate_password_hash(form_data['password'])

        # Database operation
        conn = get_db_connection()
        if not conn:
            flash('Database connection error. Please try again later.', 'danger')
            return render_template('signup.html', form_data=form_data)

        try:
            cursor = conn.cursor()

            # Check if email exists
            cursor.execute("SELECT id FROM patients WHERE email = %s", (form_data['email'],))
            if cursor.fetchone():
                flash('This email is already registered. Please use a different email or login.', 'danger')
                return render_template('signup.html', form_data=form_data)

            # Insert new patient
            cursor.execute("""
                INSERT INTO patients
                (name, email, password, age, contact, address, gender, dob)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                form_data['name'],
                form_data['email'],
                hashed_password,
                int(form_data['age']),
                form_data['contact'],
                form_data['address'],
                form_data['gender'],
                form_data['dob'] if form_data['dob'] else None
            ))

            conn.commit()
            flash('Registration successful! Please login with your new account.', 'success')
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            conn.rollback()
            flash('Registration failed due to a database error. Please try again.', 'danger')
            return render_template('signup.html', form_data=form_data)
        finally:
            if 'cursor' in locals(): cursor.close()
            if conn: conn.close()

    return render_template('signup.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        role = request.form.get('role', 'patient')

        if not email:
            flash('Please enter your email address', 'danger')
            return render_template('forgot_password.html')

        conn = get_db_connection()
        if not conn:
            flash('Database error. Please try again later.', 'danger')
            return render_template('forgot_password.html')

        try:
            cursor = conn.cursor(dictionary=True)
            table = 'patients' if role == 'patient' else 'medical_staff'
            cursor.execute(f"SELECT id FROM {table} WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user:
                # In a real app, you would send a password reset email here
                flash('If an account exists with this email, you will receive a password reset link.', 'info')
            else:
                flash('If an account exists with this email, you will receive a password reset link.', 'info')

            return redirect(url_for('login'))

        except mysql.connector.Error:
            flash('Database error. Please try again later.', 'danger')
        finally:
            if 'cursor' in locals(): cursor.close()
            if conn: conn.close()

    return render_template('forgot_password.html')

    # Rest of the function...
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/register')
def register():
    return redirect(url_for('signup'))  # Just redirect to your existing signup

# Main Routes
@app.route('/')
@login_required
def home():
    return render_template('index.html')

# Patients Routes
@app.route('/patients')
@login_required
def patients():
    if session.get('role') == 'patient':
        # For patients, redirect to their profile view
        return redirect(url_for('patient_profile'))
    
    # Only employees see the full patients list
    conn = get_db_connection()
    if not conn:
        flash('Database error', 'danger')
        return redirect(url_for('home'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM patients")
        data = cursor.fetchall()
        return render_template('employees/patients.html', patients=data)
    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'danger')
        return redirect(url_for('home'))
    finally:
        cursor.close()
        conn.close()

@app.route('/patient/profile')
@login_required
@patient_required
def patient_profile():
    """Display the profile of the currently logged-in patient"""
    conn = get_db_connection()
    if not conn:
        flash('Database error', 'danger')
        return redirect(url_for('home'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM patients WHERE email = %s", (session['email'],))
        patient = cursor.fetchone()
        
        if not patient:
            flash('Patient record not found', 'danger')
            return redirect(url_for('home'))
            
        return render_template('patients/patients_view.html', patient=patient)
        
    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'danger')
        return redirect(url_for('home'))
    finally:
        cursor.close()
        conn.close()     

@app.route('/patient/edit', methods=['GET', 'POST'])
@login_required
@patient_required
def patient_edit():
    """Allow patients to edit their own details"""
    conn = get_db_connection()
    if not conn:
        flash('Database error', 'danger')
        return redirect(url_for('patient_profile'))
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get current patient data
        cursor.execute("SELECT * FROM patients WHERE email = %s", (session['email'],))
        patient = cursor.fetchone()
        
        if not patient:
            flash('Patient record not found', 'danger')
            return redirect(url_for('patient_profile'))
            
        if request.method == 'POST':
            # Collect and validate form data
            name = request.form.get('name', '').strip()
            age = request.form.get('age', '').strip()
            gender = request.form.get('gender', '').strip()
            contact = request.form.get('contact', '').strip()
            address = request.form.get('address', '').strip()
            dob = request.form.get('dob', '').strip()
            
            # Basic validation
            errors = []
            if not name: errors.append('Name is required')
            if not age: errors.append('Age is required')
            if not gender: errors.append('Gender is required')
            if not contact: errors.append('Contact is required')
            
            if errors:
                for error in errors: flash(error, 'danger')
                return render_template('patients/edit_patient.html', patient=patient)
            
            # Update patient record
            cursor.execute("""
                UPDATE patients 
                SET name = %s, age = %s, gender = %s, contact = %s, 
                    address = %s, dob = %s
                WHERE email = %s
            """, (name, age, gender, contact, address, dob, session['email']))
            
            conn.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('patient_profile'))
            
        return render_template('patients/edit_patient.html', patient=patient)
        
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error updating profile: {err}', 'danger')
        return redirect(url_for('patient_profile'))
    finally:
        cursor.close()
        conn.close()          

@app.route('/edit_patient/<int:id>', methods=['GET', 'POST'])
@employee_required # This decorator restricts access to employees only
def edit_patient(id):
    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('patients')) # Redirect back to patients list if DB connection fails

    local_cursor = conn.cursor(dictionary=True)
    patient = None

    try:
        if request.method == 'POST':
            # Handle form submission for updating patient details
            name = request.form.get('name')
            age = request.form.get('age')
            gender = request.form.get('gender')
            dob = request.form.get('dob')
            contact = request.form.get('contact')
            address = request.form.get('address')
            email = request.form.get('email')
            # Note: For security, we generally *don't* allow password changes
            # directly from an "edit details" form. A separate "Change Password"
            # feature is recommended.

            if not all([name, age, gender, dob, contact, address, email]):
                flash('All fields are required to update patient details.', 'danger')
            else:
                # Update query to modify the patient record
                local_cursor.execute(
                    """
                    UPDATE patients
                    SET name = %s, age = %s, gender = %s, dob = %s,
                        contact = %s, address = %s, email = %s
                    WHERE id = %s
                    """,
                    (name, age, gender, dob, contact, address, email, id)
                )
                conn.commit() # Commit the changes to the database
                flash('Patient updated successfully!', 'success')
                return redirect(url_for('patients')) # Redirect to the patients list after successful update

        # For GET request (when the user first clicks 'edit'), fetch existing patient data
        local_cursor.execute("SELECT * FROM patients WHERE id = %s", (id,))
        patient = local_cursor.fetchone()

        if not patient:
            flash('Patient not found.', 'danger')
            return redirect(url_for('patients'))

    except mysql.connector.Error as err:
        conn.rollback() # Rollback any database changes if an error occurs
        flash(f"Error processing patient data: {err}", "danger")
    finally:
        local_cursor.close()
        conn.close()

    # Render the edit_patient.html template, passing the fetched patient data
    return render_template('employees/edit_patient.html', patient=patient)

@app.route('/add_patient', methods=['POST'])
@employee_required
def add_patient():
    name = request.form['name']
    age = request.form['age']
    gender = request.form['gender']
    contact = request.form['contact']
    address = request.form['address']
    email = request.form.get('email', '')
    dob = request.form.get('dob')  # <-- added this
    raw_password = request.form.get('password', '').strip()

    if not raw_password or len(raw_password) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return redirect(url_for('patients'))

    hashed_password = generate_password_hash(raw_password)

    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('patients'))

    local_cursor = conn.cursor(dictionary=True)

    try:
        local_cursor.execute(
            "INSERT INTO patients (name, age, gender, contact, address, email, dob, password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (name, age, gender, contact, address, email, dob, hashed_password)
        )
        conn.commit()
        flash('Patient added successfully', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error adding patient: {err}', 'danger')
    finally:
        local_cursor.close()
        conn.close()

    return redirect(url_for('patients'))



@app.route('/delete_patient/<int:id>')
@employee_required
def delete_patient(id):
    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('patients'))
    local_cursor = conn.cursor(dictionary=True)
    try:
        local_cursor.execute("DELETE FROM patients WHERE id = %s", (id,))
        conn.commit()
        flash('Patient deleted successfully', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error deleting patient: {err}', 'danger')
    finally:
        local_cursor.close()
        conn.close()
    return redirect(url_for('patients'))

# Doctors
@app.route('/doctors')
@login_required
@employee_required
def doctors_list_view():
    conn = get_db_connection()
    if not conn:
        flash('Database error', 'danger')
        return redirect(url_for('home'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Get all doctors
        cursor.execute("""
            SELECT id, name, specialization, department, contact, email 
            FROM medical_staff 
            WHERE role = 'doctor'
            ORDER BY name
        """)
        doctors = cursor.fetchall()
        
        return render_template('employees/doctors.html', doctors=doctors)
        
    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'danger')
        return redirect(url_for('home'))
    finally:
        if 'cursor' in locals(): cursor.close()
        if conn: conn.close()

@app.route('/doctor/<int:doctor_id>')  # Changed from id to doctor_id
def doctor_details(doctor_id):  # Renamed parameter
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('doctors_list_view'))
        
    cursor = conn.cursor(dictionary=True)
        
    cursor.execute("SELECT * FROM medical_staff WHERE id = %s AND role = 'doctor'", (doctor_id,))
    doctor = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if doctor:
        if session.get('role') == 'employee':
            return render_template('employees/doctor_details.html', doctor=doctor)
        else:
            return render_template('patients/doctor_details_view.html', doctor=doctor)
    else:
        flash('Doctor not found.', 'danger')
        return redirect(url_for('doctors_list_view'))

@app.route('/add_doctor', methods=['POST']) # This should add to medical_staff with role 'doctor'
@employee_required
def add_doctor():
    name = request.form['name']
    specialization = request.form['specialization']
    contact = request.form.get('contact', '')
    department = request.form.get('department', '')
    email = request.form.get('email', '')
    role = 'doctor' # Fixed role

    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('doctors_list_view'))
    local_cursor = conn.cursor(dictionary=True)

    try:
        local_cursor.execute(
            """INSERT INTO medical_staff (name, role, specialization, contact, department, email)
                VALUES (%s, %s, %s, %s, %s, %s)""",
            (name, role, specialization, contact, department, email)
        )
        conn.commit()
        flash('Doctor added successfully to medical staff', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error adding doctor: {err}', 'danger')
    finally:
        local_cursor.close()
        conn.close()
    return redirect(url_for('doctors_list_view'))

@app.route('/delete_doctor/<int:id>') # This should delete from medical_staff
@employee_required
def delete_doctor(id):
    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('doctors_list_view'))
    local_cursor = conn.cursor(dictionary=True)
    try:
        local_cursor.execute("DELETE FROM medical_staff WHERE id = %s AND role = 'doctor'", (id,))
        conn.commit()
        flash('Doctor deleted successfully from medical staff', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error deleting doctor: {err}', 'danger')
    finally:
        local_cursor.close()
        conn.close()
    return redirect(url_for('doctors_list_view'))

@app.route('/staff')
@employee_required
def staff():
    conn = get_db_connection()
    if not conn:
        flash('Database connection error during staff view.', 'danger')
        return render_template('index.html', staff=[], total_staff=0, added_today=0)

    local_cursor = conn.cursor(dictionary=True)
    staff_members = []
    total_staff = 0
    added_today = 0

    try:
        # Get ALL staff (including doctors)
        local_cursor.execute("""
            SELECT id, name, role, contact, email, created_at
            FROM medical_staff
            ORDER BY role, name
        """)
        staff_members = local_cursor.fetchall()

        # Get total count of all staff
        local_cursor.execute("SELECT COUNT(*) as count FROM medical_staff")
        total_staff = local_cursor.fetchone()['count']

        # Get count of staff added today
        local_cursor.execute("""
            SELECT COUNT(*) as count FROM medical_staff
            WHERE DATE(created_at) = CURDATE()
        """)
        added_today = local_cursor.fetchone()['count']

    except mysql.connector.Error as err:
        flash(f"Error fetching staff data: {err}", "danger")
    finally:
        local_cursor.close()
        conn.close()

    return render_template(
        'employees/staff.html',
        staff=staff_members,
        total_staff=total_staff,
        added_today=added_today
    )


@app.route('/add_staff', methods=['POST'])
@employee_required # Assuming this decorator is correctly defined and imported
def add_staff():
    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        contact = request.form.get('contact')
        email = request.form.get('email')

        # Server-side validation for 'contact'
        if not contact or contact.strip() == '':
            flash("Contact information is required.", 'danger')
            return redirect(url_for('staff'))

        # Ensure email is not None; convert to empty string if it is.
        # This prevents 'Column 'email' cannot be null' error if DB column is NOT NULL.
        if email is None:
            email = ''
        # Optional: strip whitespace from email
        # email = email.strip()

        # Validate the role against allowed roles
        allowed_roles = ['doctor', 'nurse', 'admin', 'receptionist']
        if role not in allowed_roles:
            flash(f"Invalid role: {role}. Please choose from: {', '.join(allowed_roles)}", 'danger')
            return redirect(url_for('staff'))

        # Generate a secure temporary password
        characters = string.ascii_letters + string.digits + string.punctuation
        temp_raw_password = ''.join(secrets.choice(characters) for i in range(12)) # Generates a 12-char random password
        hashed_password = generate_password_hash(temp_raw_password) # Hash the password

        # Determine specialization value based on role
        # Ensure the string length matches the VARCHAR limit in your DB for 'p_specialization'
        specialization_value = '' # Default for roles without specific specialization

        if role == 'doctor':
            specialization_value = 'General' # Example specialization for doctors
            # If you have a 'specialization' field in your HTML form for doctors,
            # you'd get it like: request.form.get('specialization', 'General')
        elif role == 'nurse':
            specialization_value = 'Nursing'
        elif role == 'admin' or role == 'receptionist':
            specialization_value = 'N/A' # Not Applicable for these roles

        conn = None
        cursor = None
        try:
            conn = get_db_connection() # Get a database connection
            cursor = conn.cursor()

            # --- CRITICAL: Call the stored procedure with the CORRECT number and ORDER of arguments ---
            # You must have previously confirmed the signature of your 'add_medical_staff' procedure
            # using 'SHOW CREATE PROCEDURE hospital_db.add_medical_staff;' in MySQL.
            # Assuming the order is: (name, role, contact, email, password, department, specialization)
            cursor.callproc('add_medical_staff', (
                name,
                role,
                contact,
                email,
                hashed_password,
                None,  # Assuming 'department' is nullable and not collected from the form
                specialization_value
            ))

            conn.commit() # Commit the transaction to save changes to the database
            flash(f'Staff member "{name}" ({role}) added successfully.', 'success') # Success message (without displaying password)

        except mysql.connector.Error as e:
            # Catch specific MySQL errors for better debugging
            flash(f'Error adding staff member: {e}', 'danger')
            if conn:
                conn.rollback() # Rollback changes if an error occurs
        except Exception as e:
            # Catch any other unexpected Python errors
            flash(f'An unexpected error occurred: {e}', 'danger')
            if conn:
                conn.rollback()
        finally:
            # Ensure cursor and connection are closed in all cases
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return redirect(url_for('staff')) # Redirect back to the staff list page after action

@app.route('/delete_staff/<int:id>')
@employee_required
def delete_staff_member(id):
    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('staff'))
    
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        
        # First get staff details for confirmation message
        cursor.execute("SELECT name, role FROM medical_staff WHERE id = %s", (id,))
        staff = cursor.fetchone()
        
        if not staff:
            flash('Staff member not found', 'danger')
            return redirect(url_for('staff'))
        
        # Check if trying to delete own account
        if session.get('user_id') == id:
            flash('You cannot delete your own account', 'danger')
            return redirect(url_for('staff'))
        
        # Delete the staff member (including doctors)
        cursor.execute("DELETE FROM medical_staff WHERE id = %s", (id,))
        conn.commit()
        
        flash(f"{staff['role'].title()} {staff['name']} deleted successfully", 'success')
        
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error deleting staff member: {err}', 'danger')
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
    
    return redirect(url_for('staff'))

# Appointments
@app.route('/appointments')
def appointments():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return render_template('index.html')  # Or an error page

    local_cursor = conn.cursor(dictionary=True)

    query = """
        SELECT a.id, p.name AS patient_name, d.name AS doctor_name, a.appointment_date, a.status, a.notes
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN medical_staff d ON a.staff_id = d.id AND d.role = 'doctor'
    """

    all_appointments = []
    all_patients_list = []
    all_doctors_list = []

    try:
        if session.get('role') == 'patient':
            user_email = session.get('email')
            local_cursor.execute("SELECT id FROM patients WHERE email = %s", (user_email,))
            patient_record = local_cursor.fetchone()

            if patient_record:
                local_cursor.execute(
                    query + " WHERE a.patient_id = %s ORDER BY a.appointment_date DESC",
                    (patient_record['id'],)
                )
                all_appointments = local_cursor.fetchall()
            else:
                flash("Patient record not found for your account.", "warning")

            # ✅ Load doctors for dropdown
            local_cursor.execute(
                "SELECT id, name, specialization FROM medical_staff WHERE role = 'doctor' ORDER BY name"
            )
            all_doctors_list = local_cursor.fetchall()

        else:  # Employee
            local_cursor.execute(query + " ORDER BY a.appointment_date DESC")
            all_appointments = local_cursor.fetchall()

            local_cursor.execute("SELECT id, name FROM patients ORDER BY name")
            all_patients_list = local_cursor.fetchall()

            local_cursor.execute(
                "SELECT id, name, specialization FROM medical_staff WHERE role = 'doctor' ORDER BY name"
            )
            all_doctors_list = local_cursor.fetchall()

    except mysql.connector.Error as err:
        flash(f"Error fetching appointments: {err}", "danger")
    finally:
        local_cursor.close()
        conn.close()

    template_name = 'patients/appointments_view.html' if session.get('role') == 'patient' else 'employees/appointments.html'

    return render_template(
        template_name,
        appointments=all_appointments,
        patients=all_patients_list,  # only for employee
        doctors=all_doctors_list     # for dropdown
    )
  # for employee form (using medical_staff as doctors)


@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if not session.get('logged_in'):
        flash('Please log in to book an appointment.', 'warning')
        return redirect(url_for('login'))

    # Get form data
    doctor_staff_id = request.form.get('doctor_id')
    appointment_date = request.form.get('appointment_date')
    notes = request.form.get('notes', '')

    # Validate required fields
    if not doctor_staff_id or not appointment_date:
        flash('Doctor and appointment date are required.', 'danger')
        return redirect(url_for('appointments'))

    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('appointments'))

    local_cursor = conn.cursor(dictionary=True)
    patient_id = None

    try:
        # PATIENT BOOKING FLOW
        if session.get('role') == 'patient':
            # Automatically get patient ID from session
            local_cursor.execute("SELECT id FROM patients WHERE email = %s", (session.get('email'),))
            patient_record = local_cursor.fetchone()

            if not patient_record:
                flash('Patient record not found.', 'danger')
                return redirect(url_for('appointments'))

            patient_id = patient_record['id']
            status = 'Scheduled'  # Default status for patients

        # EMPLOYEE BOOKING FLOW
        elif session.get('role') == 'employee':
            patient_id = request.form.get('patient_id')
            if not patient_id:
                flash('Patient selection is required for staff bookings.', 'danger')
                return redirect(url_for('appointments'))

            status = request.form.get('status', 'Scheduled')  # Employees can set status

        else: # This 'else' block handles cases where the role is neither 'patient' nor 'employee'
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('appointments'))

        # Verify the selected staff is a doctor
        local_cursor.execute("SELECT id FROM medical_staff WHERE id = %s AND role = 'doctor'", (doctor_staff_id,))
        if not local_cursor.fetchone():
            flash('Invalid doctor selected.', 'danger')
            return redirect(url_for('appointments'))

        # Insert the appointment
        local_cursor.execute(
            "INSERT INTO appointments (patient_id, staff_id, appointment_date, status, notes) VALUES (%s, %s, %s, %s, %s)",
            (patient_id, doctor_staff_id, appointment_date, status, notes)
        )
        conn.commit()
        flash('Appointment booked successfully!', 'success')

    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error booking appointment: {err}', 'danger')
    finally:
        local_cursor.close()
        conn.close()

    return redirect(url_for('appointments'))

@app.route('/delete_appointment/<int:appointment_id>')
def delete_appointment(appointment_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('appointments'))

    local_cursor = conn.cursor(dictionary=True)

    try:
        # For patients, verify they own the appointment
        if session.get('role') == 'patient':
            local_cursor.execute("""
                SELECT a.id
                FROM appointments a
                JOIN patients p ON a.patient_id = p.id
                WHERE p.email = %s AND a.id = %s
            """, (session.get('email'), appointment_id))
            if not local_cursor.fetchone():
                flash("You can only cancel your own appointments.", "danger")
                return redirect(url_for('appointments'))

        # Delete the appointment
        local_cursor.execute("DELETE FROM appointments WHERE id = %s", (appointment_id,))
        conn.commit()
        flash('Appointment cancelled successfully', 'success')

    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error cancelling appointment: {err}', 'danger')
    finally:
        local_cursor.close()
        conn.close()

    return redirect(url_for('appointments'))

@app.route('/billing')
@login_required
def billing():
    """Display billing records for patients and employees"""
    conn = get_db_connection()
    if not conn: 
        flash('Database connection error', 'danger')
        return redirect(url_for('home'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Base query for billing records
        base_query = """
            SELECT b.id, p.name AS patient_name, 
                   b.amount, b.payment_date, b.status, b.description 
            FROM billing b
            INNER JOIN patients p ON b.patient_id = p.id
        """
        
        billing_records = []
        patients = []

        if session.get('role') == 'patient':
            # Patient can only see their own bills
            cursor.execute("SELECT id FROM patients WHERE email = %s", (session['email'],))
            patient_user = cursor.fetchone()
            if patient_user:
                cursor.execute(
                    base_query + " WHERE b.patient_id = %s ORDER BY b.payment_date DESC", 
                    (patient_user['id'],)
                )
                billing_records = cursor.fetchall()
        else:
            # Employee can see all bills
            cursor.execute(base_query + " ORDER BY b.payment_date DESC")
            billing_records = cursor.fetchall()
            
            # Get all patients for dropdown
            cursor.execute("SELECT id, name FROM patients ORDER BY name")
            patients = cursor.fetchall()

        return render_template(
            'employees/billing.html' if session.get('role') == 'employee' else 'patients/billing_view.html',
            billing=billing_records,
            patients=patients
        )

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
        return redirect(url_for('home'))
    finally:
        if 'cursor' in locals(): cursor.close()
        if conn: conn.close()


@app.route('/add_billing', methods=['POST'])
@employee_required
def add_billing():
    """Add a new billing record"""
    try:
        patient_id = request.form['patient_id']
        amount = float(request.form['amount'])
        payment_date = request.form['payment_date']
        
        if amount <= 0:
            flash('Amount must be positive', 'danger')
            return redirect(url_for('billing'))

        conn = get_db_connection()
        if not conn:
            flash('Database error.', 'danger')
            return redirect(url_for('billing'))
            
        try:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO billing (patient_id, amount, payment_date) 
                VALUES (%s, %s, %s)""",
                (patient_id, amount, payment_date)
            )
            conn.commit()
            flash('Bill added successfully', 'success')
        except mysql.connector.Error as err:
            conn.rollback()
            flash(f'Error adding bill: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()
            
    except ValueError:
        flash('Invalid amount format', 'danger')
    except KeyError as e:
        flash(f'Missing required field: {e}', 'danger')
        
    return redirect(url_for('billing'))


@app.route('/delete_billing/<int:id>')
@employee_required
def delete_billing(id):
    """Delete a billing record"""
    conn = get_db_connection()
    if not conn:
        flash('Database error.', 'danger')
        return redirect(url_for('billing'))
        
    try:
        cursor = conn.cursor()
        # Verify bill exists first
        cursor.execute("SELECT id FROM billing WHERE id = %s", (id,))
        if not cursor.fetchone():
            flash('Bill not found', 'danger')
            return redirect(url_for('billing'))
            
        cursor.execute("DELETE FROM billing WHERE id = %s", (id,))
        conn.commit()
        flash('Bill deleted successfully', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error deleting bill: {err}', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('billing'))


# Medical Records
@app.route('/records')
@login_required
def records():
    """Display medical records based on user role"""
    conn = get_db_connection()
    if not conn:
        flash('Database connection error', 'danger')
        return redirect(url_for('home'))
    
    try:
        cursor = conn.cursor(dictionary=True)
        
        if session.get('role') == 'patient':
            # Patient can only see their own records
            cursor.execute("""
                SELECT r.*, p.name AS patient_name 
                FROM medical_records r
                JOIN patients p ON r.patient_id = p.id
                WHERE p.email = %s
                ORDER BY r.record_date DESC
            """, (session['email'],))
            records = cursor.fetchall()
            return render_template('patients/my_records.html', records=records)
        else:
            # Employee can see all records
            cursor.execute("""
                SELECT r.*, p.name AS patient_name 
                FROM medical_records r
                JOIN patients p ON r.patient_id = p.id
                ORDER BY r.record_date DESC
            """)
            records = cursor.fetchall()
            
            # Get patients for dropdown
            cursor.execute("SELECT id, name FROM patients ORDER BY name")
            patients = cursor.fetchall()
            
            return render_template('employees/all_records.html', 
                                 records=records, 
                                 patients=patients)
    
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
        return redirect(url_for('home'))
    finally:
        if 'cursor' in locals(): cursor.close()
        if conn: conn.close()


@app.route('/add_record', methods=['POST'])
@employee_required
def add_record():
    """Add a new medical record"""
    try:
        patient_id = request.form['patient_id']
        diagnosis = request.form['diagnosis']
        treatment = request.form['treatment']
        notes = request.form.get('notes', '')
        
        conn = get_db_connection()
        if not conn:
            flash('Database error', 'danger')
            return redirect(url_for('records'))
            
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO medical_records 
                (patient_id, diagnosis, treatment, notes) 
                VALUES (%s, %s, %s, %s)
            """, (patient_id, diagnosis, treatment, notes))
            conn.commit()
            flash('Record added successfully', 'success')
        except mysql.connector.Error as err:
            conn.rollback()
            flash(f'Error adding record: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()
            
    except KeyError as e:
        flash(f'Missing required field: {e}', 'danger')
        
    return redirect(url_for('records'))


@app.route('/delete_record/<int:id>')
@employee_required
def delete_record(id):
    """Delete a medical record"""
    conn = get_db_connection()
    if not conn:
        flash('Database error', 'danger')
        return redirect(url_for('records'))
        
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM medical_records WHERE id = %s", (id,))
        conn.commit()
        flash('Record deleted successfully', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f'Error deleting record: {err}', 'danger')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('records'))

if __name__ == '__main__':
    app.run(debug=True)