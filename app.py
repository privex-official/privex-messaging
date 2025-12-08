from flask import Flask, flash, render_template, redirect, request, session,url_for, Response,jsonify

from meeting_id_creation import *
from functools import wraps
from meeting_db import *
from flask_socketio import SocketIO, emit, join_room, leave_room
from message_db import MessageDB
from hashing import *
from todo_db import *
from datetime import datetime, timedelta, timezone
import random
import re
from markupsafe import Markup, escape
from dotenv import load_dotenv
import os
from send_email import *
from dh_rsa import *
from generate import *
from utility import E2E
from non_repudiation import *
import sqlite3
#decalre decorator for login require

UPLOAD_FOLDER = 'uploads/'  # or any path where you want to store files
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # create folder if not exists


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.secret_key = os.environ.get('APP_SECRET_KEY', 'default_secret_key')
socketio = SocketIO(app)  # Add async_mode='eventlet' if needed
@socketio.on('join')
def handle_join(data):
    room = data['room']
    user = session.get('username')
    join_room(room)
    emit('message', {'user': 'System', 'text': f'{user} joined the chat'}, to=room)

@socketio.on('send_message')
def handle_send_message(data):
    room = data['room']
    user = session.get('username')
    raw_msg = data['message']

    
    private_key_obj = RSA.import_key(session["private_key"])
    public_key=get_public_key(user)
    signature = sign_message(private_key_obj, raw_msg,session["username"],room)
    is_verified = verify_signature(public_key, raw_msg, signature,user,room)
    if not is_verified:
        leave_room(room)
       
    
    
    e2e=E2E()

    # Encrypt the message using the symmetric key
    msg = e2e.encrypt(raw_msg.encode(),room)

    MessageDB.add_message(room, user, msg)
    
    emit('message', {'user': user, 'text': raw_msg}, to=room)





@app.template_filter('linkify')
def linkify(text):
    url_regex = r'(https?://[^\s]+)'
    escaped_text = escape(text)

    def replace_url(match):
        url = match.group(0)
        # Build the safe <a> tag and mark only it as safe
        return Markup(f'<a href="{escape(url)}" class="text-blue-600 underline" target="_blank">{escape(url)}</a>')  # nosec B704

    # Here, `re.sub` will mix safe Markup objects with escaped text safely
    return re.sub(url_regex, replace_url, escaped_text)










#-------------------- Block logic-----------------









@app.route('/block_unblock_user', methods=['POST'])
@login_required
def block_unblock_user():
    data = request.json
    username = data['username']
    meeting_id = data['meetingId']
    is_blocked = data['block']  # true (block) or false (unblock)

    

    rsa = RSAEncryption()
    host_difi=DiffieHellman(P,G)
    server_difi=DiffieHellman(P,G)
    
    # host_difi_key=host_difi.compute_shared_secret(server_difi.public_key)
    # server_difi_key=server_difi.compute_shared_secret(host_difi.public_key)
    
    encrypt_host_public_key = rsa.encrypt(rsa.public_key, str(host_difi.public_key).encode())
    encrypt_server_public_key = rsa.encrypt(rsa.public_key, str(server_difi.public_key).encode())
    private_key = rsa.private_key

   
   
    UserMeetingDB.toggle_block_and_update_key(username,meeting_id,encrypt_host_public_key,
                                              server_difi,private_key)
    UserMeetingDB.update_difi_key(MeetingDB.get_host(meeting_id),meeting_id,encrypt_server_public_key,
                                  host_difi,private_key)

    # Emit socket event to forcibly disconnect if blocked
    if is_blocked:
        socketio.emit('force_disconnect', {'user_id': username}, room=meeting_id)

    return jsonify({'success': True})





















@app.route('/meeting/<meetingId>/assign_todo',methods=['GET','POST'])
@login_required
def assign_todo(meetingId):
    if not MeetingDB.meeting_exists(meetingId):
        
        return '<h1>meeting not found</h1>'
    if session['username'] not in UserMeetingDB.get_users_for_meeting(meetingId):
        return '<h1>you are not a member </h1>'
  

    if request.method == 'POST':
        taskName = request.form['taskName']
        uploadRequired = 'uploadRequired' in request.form
        comment = request.form['comment']
        assignedTo = request.form['assignedTo']
        deadline_raw = request.form['deadline']  # e.g., '2025-06-24T23:45'

        # Convert to 'YYYY-MM-DD HH:MM:SS'
        # try:
        #     deadline = datetime.strptime(deadline_raw, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M:%S")
        # except ValueError:
        #     return "<h1>Invalid deadline format</h1>"

        try:
            deadline_obj = datetime.strptime(deadline_raw, "%Y-%m-%dT%H:%M")
            if deadline_obj <= datetime.now():
                flash("Deadline must be in the future")
                return redirect(request.url)
            deadline = deadline_obj.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return "<h1>Invalid deadline format</h1>"


        TaskDB.add_task(
            meetingId,
            session['username'],
            assignedTo,
            taskName,
            uploadRequired,
            comment,
            deadline
        )
        return redirect(url_for('meeting', meetingId=meetingId))


        
        
        
        
    users = UserMeetingDB.get_users_for_meeting(meetingId)
    if session['username'] in users:
        users.remove(session['username'])

    return render_template('todo_assignments.html',meeting_id=meetingId,hosted_by=session['username'],users=users)














@app.route('/meeting/<meetingId>/set_cohost',methods=['POST'])
@login_required
def set_co_host(meetingId):
    if request.method == 'POST' and session['username']==MeetingDB.get_host(meetingId):
        co_host=request.form['cohost']
        MeetingDB.update_co_host(meeting_id=meetingId,new_co_host=co_host)
        return redirect(url_for('meeting', meetingId=meetingId))
    return Response(status=400)
        

@app.route('/meeting/<meetingId>/delete_room')
@login_required
def delete_room(meetingId):
    #delete all todo for a meetingid
    TaskDB.delete_tasks_for_meeting(meetingId)
    MessageDB.delete_messages_by_meeting(meetingId)
    MeetingDB.delete_meeting(meetingId)
    UserMeetingDB.delete_all_by_meeting_id(meetingId)
    #delete the db of aes key and master aes keys from db  need to executed
    return redirect(url_for('dashboard'))
    
    




@app.route('/meeting/<meetingId>/leave_room')
@login_required
def leave_room(meetingId):
    UserMeetingDB.delete_all_by_user_id(session['username'])
    socketio.emit('message', {'user': 'System', 'text': f'{session["username"]} left the chat'}, room=meetingId)
    if session['username'] == MeetingDB.get_host(meetingId):
        if MeetingDB.get_co_host(meetingId): 
            MeetingDB.update_host(meetingId, MeetingDB.get_co_host(meetingId))
            MeetingDB.set_co_host(meetingId, None)
            e2e=E2E()
            e2e.format_key(meetingId,UserMeetingDB.get_users_for_meeting(meetingId))
        else:
            delete_room(meetingId)
        return redirect(url_for('dashboard'))

    elif UserMeetingDB.get_member_count(meetingId) == 0:
        delete_room(meetingId)
        return redirect(url_for('dashboard'))

    # ✅ Fallback for all other users
    return redirect(url_for('dashboard'))

    
    







@app.route('/meeting/<meetingId>/show_todo', methods=['GET', 'POST'])
@login_required
def show_todo(meetingId):
    if not MeetingDB.meeting_exists(meetingId):
        return '<h1>Meeting not found</h1>'
    
    if session['username'] not in UserMeetingDB.get_users_for_meeting(meetingId):
        return '<h1>You are not a member of this meeting</h1>'

    # Fetch all tasks for this meeting
    raw_tasks = TaskDB.get_tasks_for_meeting(meetingId)

    meeting_name = MeetingDB.get_title_by_id(meetingId)

    # Convert to dicts for rendering
    todo_tasks = []
    for row in raw_tasks:
        todo_tasks.append({
            'id': row[0],
            'meetingId': row[1],
            'assigned_by': row[2],
            'assigned_to': row[3],
            'taskName': row[4],
            'uploadRequired': bool(row[5]),
            'comment': row[6],
            'deadline': row[7],
            'isDone': bool(row[8])
        })

    return render_template('show_todo.html', todo_tasks=todo_tasks, meetingId=meetingId, meeting_name = meeting_name)



@app.route("/task/<int:task_id>")
def view_task(task_id):
    task=TaskDB.get_task_by_id(task_id)
    roomname=MeetingDB.get_title_by_id(task['meetingId'])
    if task:
        return render_template("view_task.html", task=task,roomname=roomname)
    else:
        return "Task not found", 404














DB_FILES = {
    "meetings": "meetings.db",
    "messages": "data.db",
    "tasks": "todo.db"
}

# -----------------------
# Get tables from a DB
# -----------------------
def get_tables(db_key):
    db_path = DB_FILES[db_key]
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in c.fetchall()]
    conn.close()
    return tables

# -----------------------
# Execute SQL
# -----------------------
def execute_sql(db_key, sql):
    db_path = DB_FILES.get(db_key)
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    try:
        c.execute(sql)

        if sql.strip().lower().startswith("select"):
            rows = c.fetchall()
            headers = [col[0] for col in c.description]
            conn.close()
            return headers, rows

        conn.commit()
        conn.close()
        return ["Status"], [["Success"]]

    except Exception as e:
        conn.close()
        return ["Error"], [[str(e)]]


# -----------------------
# Main console page
# -----------------------
@app.route("/sql-console", methods=["GET", "POST"])
@login_required
def sql_console():
    if(session["username"]!="rohan"):
        return "404 Page not Found", 404
    selected_db = request.form.get("database", "meetings")
    selected_table = request.form.get("table", "")
    custom_sql = request.form.get("sql", "")

    tables = get_tables(selected_db)
    headers, rows = [], []

    # Auto-run: SELECT * FROM chosen table
    if selected_table:
        query = f"SELECT * FROM {selected_table}"
        headers, rows = execute_sql(selected_db, query)

    # Custom SQL
    if custom_sql.strip() != "":
        headers, rows = execute_sql(selected_db, custom_sql)

    return render_template(
        "sql_console.html",
        databases=DB_FILES,
        tables=tables,
        selected_db=selected_db,
        selected_table=selected_table,
        headers=headers,
        rows=rows
    )

# -----------------------
# AJAX endpoint to update tables
# -----------------------
@app.route("/get_tables/<db_key>")
def get_tables_api(db_key):
    return jsonify(get_tables(db_key))







@app.route('/')
def welcome():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('welcome.html')


@app.route('/login_page', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        
        password = request.form['password']
        password=sha256(password)
        print("-------------- password hashed -------------------")
        if UserDB.user_exists(username):
            print("------------- enter into if part---------")
            if password != UserDB.get_password(username):
                message = "Invalid password"
                print("-------------invalid password---------------")
                return render_template('login_page.html', message=message)
            # Successful login
            session['username'] = username
            private_key_obj = get_private_key(username, password=password)
            private_key_pem = private_key_obj.export_key().decode()  # export unencrypted PEM
            session["private_key"] = private_key_pem
            # session['private_key']=os.join()
            print("_____________________ entered in login -------------------------")
            
            return redirect(url_for('dashboard'))
        else:
            # Username not found, redirect to signup with message
            return redirect(url_for('signup', message="Username not found. Please sign up."))
    return render_template('login_page.html')


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    # Check if we should keep previously verified email
    keep_email = request.args.get('keep_email')

    # If this is a fresh GET (user just opened /signup), clear old verification
    if request.method == 'GET' and not keep_email:
        session.pop('signup_email_verified', None)
        session.pop('signup_verified_email', None)

    message = request.args.get('message')
    email_verified = session.get('signup_email_verified', False)
    verified_email = session.get('signup_verified_email', '')

    if request.method == 'GET':
        return render_template(
            'signup_page.html',
            message=message,
            email_verified=email_verified,
            verified_email=verified_email,
        )


    # ---------- POST: final signup submit ----------
    if request.form['password1'] != request.form['password2']:
        return render_template(
            'signup_page.html',
            message="Passwords do not match.",
            email_verified=email_verified,
            verified_email=verified_email,
        )

    username = request.form['username'].strip()
    raw_password = request.form['password1']
    email = request.form['email'].strip()
    name = request.form['name'].strip()

    # ✅ Enforce email verification
    if not email_verified or email != verified_email:
        return render_template(
            'signup_page.html',
            message="Please verify your email before signing up.",
            email_verified=email_verified,
            verified_email=verified_email,
        )

    if UserDB.user_exists(username):
        message = "Username already exists"
        return redirect(url_for('signup', message=message))

    if UserDB.email_exists(email):
        message = "Email already in use"
        return redirect(url_for('signup', message=message))

    password = sha256(raw_password)

    # Create user + keys (same as before)
    UserDB.add_user(user_id=username, name=name, email=email, password=password)
    generate_keys(username=username, password=password)
    session['username'] = username
    private_key_obj = get_private_key(username, password=password)
    private_key_pem = private_key_obj.export_key().decode()
    session["private_key"] = private_key_pem

    # Clear email verification flags now that account is created
    session.pop('signup_email_verified', None)
    session.pop('signup_verified_email', None)

    return redirect(url_for('dashboard'))






@app.route('/signup_send_otp')
def signup_send_otp():
    # Email comes from query param: /signup_send_otp?email=...
    email = request.args.get('email', '').strip()

    if not email:
        return redirect(url_for('signup', message="Please enter an email to verify."))

    # Optional: you can block already-used emails
    if UserDB.email_exists(email):
        return redirect(url_for('signup', message="Email already in use. Please use a different email."))

    # Generate OTP
    otp = random.randint(1000, 9999)

    # Store OTP + email in session
    session['signup_email_pending'] = email
    session['signup_email_otp'] = str(otp)
    session['signup_email_otp_expiry'] = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    # Send mail
    load_dotenv()
    sender_email = os.environ.get('APP_EMAIL')
    app_password = os.environ.get('APP_EMAIL_CODE')

    try:
        send_message_email(
            sender_email=sender_email,
            sender_app_password=app_password,
            receiver_email=email,
            subject="Privex signup email verification",
            body=f"Your email verification OTP is: {otp}\n\nThis code is valid for 5 minutes."
        )
    except Exception as e:
        # Clean pending data
        session.pop('signup_email_pending', None)
        session.pop('signup_email_otp', None)
        session.pop('signup_email_otp_expiry', None)
        return redirect(url_for('signup', message="Failed to send OTP. Please try again."))

    # Go to OTP page
    return redirect(url_for('verify_signup_email'))






@app.route('/verify_signup_email', methods=['GET', 'POST'])
def verify_signup_email():
    if 'signup_email_pending' not in session or 'signup_email_otp' not in session:
        return redirect(url_for('signup', message="Please start email verification again."))

    pending_email = session['signup_email_pending']

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        real_otp = session.get('signup_email_otp')
        expiry_iso = session.get('signup_email_otp_expiry')

        # Check expiry
        try:
            expiry = datetime.fromisoformat(expiry_iso)
            if datetime.now(timezone.utc) > expiry:
                # Clear
                session.pop('signup_email_pending', None)
                session.pop('signup_email_otp', None)
                session.pop('signup_email_otp_expiry', None)
                return redirect(url_for('signup', message="OTP expired. Please verify your email again."))
        except Exception:
            session.pop('signup_email_pending', None)
            session.pop('signup_email_otp', None)
            session.pop('signup_email_otp_expiry', None)
            return redirect(url_for('signup', message="Something went wrong. Please verify your email again."))

        if entered_otp != real_otp:
            return render_template(
                'verify_signup_email.html',
                email=pending_email,
                message="Invalid OTP. Please try again."
            )

        # ✅ OTP correct: mark email as verified
        verified_email = pending_email
        session['signup_email_verified'] = True
        session['signup_verified_email'] = verified_email

        # Clear OTP-only keys
        session.pop('signup_email_pending', None)
        session.pop('signup_email_otp', None)
        session.pop('signup_email_otp_expiry', None)

        # Back to signup form with verified email
        return redirect(url_for(
            'signup',
            message="Email verified successfully. Please complete the signup form.",
            keep_email=1
        ))

    # GET: show OTP form
    return render_template('verify_signup_email.html', email=pending_email, message=None)







@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        if not email:
            flash("Please enter your registered email address.", "error")
            return render_template('forgot_password.html')

        if not UserDB.email_exists(email):
            flash("No account found with that email.", "error")
            return render_template('forgot_password.html')

        # Get corresponding user id
        user_id = UserDB.get_userid_by_email(email)
        if not user_id:
            flash("No account found with that email.", "error")
            return render_template('forgot_password.html')

        # Generate 4-digit OTP
        otp = random.randint(1000, 9999)

        # Save in session (simple server-side store)
        session['reset_email'] = email
        session['reset_user_id'] = user_id
        session['reset_otp'] = str(otp)
        session['reset_otp_expiry'] = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

        # Send OTP via email
        load_dotenv()
        sender_email = os.environ.get('APP_EMAIL')
        app_password = os.environ.get('APP_EMAIL_CODE')

        try:
            send_message_email(
                sender_email=sender_email,
                sender_app_password=app_password,
                receiver_email=email,
                subject="Privex password reset OTP",
                body=f"Your password reset OTP is: {otp}\n\nThis code is valid for 5 minutes."
            )
        except Exception as e:
            flash("Failed to send OTP. Please try again later.", "error")
            return render_template('forgot_password.html')

        flash("OTP sent to your email. Please check your inbox.", "info")
        return redirect(url_for('verify_otp'))

    return render_template('forgot_password.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # If user did not come from forgot_password
    if 'reset_email' not in session or 'reset_otp' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        real_otp = session.get('reset_otp')
        expiry_iso = session.get('reset_otp_expiry')

        # Check expiry
        try:
            expiry = datetime.fromisoformat(expiry_iso)
            if datetime.now(timezone.utc) > expiry:
                flash("OTP has expired. Please request a new one.", "error")
                # Clear old OTP
                session.pop('reset_otp', None)
                session.pop('reset_otp_expiry', None)
                return redirect(url_for('forgot_password'))
        except Exception:
            # If expiry is malformed, force restart
            flash("Something went wrong. Please try again.", "error")
            return redirect(url_for('forgot_password'))

        if entered_otp != real_otp:
            flash("Invalid OTP. Please try again.", "error")
            return render_template('verify_otp.html')

        # Mark OTP as verified; don't need the code anymore
        
        session['otp_verified'] = True
        session.pop('reset_otp', None)
        session.pop('reset_otp_expiry', None)

        return redirect(url_for('reset_password'))

    return render_template('verify_otp.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Ensure OTP step completed
    if not session.get('otp_verified') or 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        p1 = request.form.get('password1', '')
        p2 = request.form.get('password2', '')

        if not p1 or not p2:
            flash("Please fill both password fields.", "error")
            return render_template('reset_password.html')

        if p1 != p2:
            flash("Passwords do not match.", "error")
            return render_template('reset_password.html')

        # Hash new password with existing sha256 helper
        hashed = sha256(p1)
        reset_keys_force_delete( session['reset_user_id'],hashed)

        user_id = session['reset_user_id']
        UserDB.update_password(user_id, hashed)

        # Clean up reset session keys
        session.pop('reset_email', None)
        session.pop('reset_user_id', None)
        session.pop('otp_verified', None)

        flash("Password reset successful. You can now log in.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')





from flask import jsonify, request

@app.route('/search_meetings')
@login_required
def search_meetings():
    user_id = session['username']
    query = request.args.get('q', '').lower()
    results = []

    for title, host, meeting_id in get_user_meetings(user_id):
        if query in title.lower() or query in host.lower():
            results.append({
                "title": title,
                "host": host,
                "meetingId": meeting_id
            })

    return jsonify(results)

def get_user_meetings(user_id):
    meetings = UserMeetingDB.get_meetings_for_user(user_id)
    return [(MeetingDB.getMeetingTitle(m), MeetingDB.get_host(m), m) for m in meetings]



@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['username']
    meetings = UserMeetingDB.get_meetings_for_user(user_id=user_id)

    createdMeetings = []
    joinedMeeting = []
    created_with_members = []
    joined_with_members = []

    hostCount = 0
    totalCount = len(meetings)
    tuple_meetings=[]
    for i in meetings:
        temp=(MeetingDB.getMeetingTitle(i),MeetingDB.get_host(i),i)
        tuple_meetings.append(temp)

    for meeting_id in meetings:
        if MeetingDB.get_host(meeting_id) == user_id:
            hostCount += 1
            createdMeetings.append(meeting_id)
            created_with_members.append({
                "meeting_id": meeting_id,
                "members": len(UserMeetingDB.get_users_for_meeting(meeting_id))
            })
        else:
            joinedMeeting.append(meeting_id)
            joined_with_members.append({
                "meeting_id": meeting_id,
                "members": len(UserMeetingDB.get_users_for_meeting(meeting_id))
            })

    joinCount = totalCount - hostCount
        # ✅ Fetch todos assigned *to* the user
    tasks_assigned_to = TaskDB.get_all_tasks()
    user = session['username']
    filter_status = request.args.get('status')  # "completed" or "pending" or None
    filter_meeting_id = request.args.get('meeting_id')  # meeting_id or None
    def parse_due_date(task):
        try:
            if isinstance(task[7], str):
                task = list(task)  # Convert tuple to list to allow mutation
                task[7] = datetime.strptime(task[7], "%Y-%m-%d %H:%M:%S")
            return task
        except Exception as e:
            
            return task
    assigned_to_me = TaskDB.get_all_tasks()
    assigned_by_me = TaskDB.get_all_tasks()
    assigned_to_me = [parse_due_date(task) for task in assigned_to_me]
    assigned_by_me=[parse_due_date(task) for task in assigned_by_me]

    # Filter assigned to me
    assigned_to_me = [task for task in assigned_to_me if task[3] == user]
    
    if filter_status == 'completed':
        assigned_to_me = [task for task in assigned_to_me if task[8]]
    elif filter_status == 'pending':
        assigned_to_me = [task for task in assigned_to_me if not task[8]]
    if filter_meeting_id:
        assigned_to_me = [task for task in assigned_to_me if task[1] == filter_meeting_id]

    # Filter assigned by me
    assigned_by_me = [task for task in assigned_by_me if task[2] == user]
    if filter_status == 'completed':
        assigned_by_me = [task for task in assigned_by_me if task[8]]
    elif filter_status == 'pending':
        assigned_by_me = [task for task in assigned_by_me if not task[8]]
    if filter_meeting_id:
        assigned_by_me = [task for task in assigned_by_me if task[1] == filter_meeting_id]

    # Get meetings and titles for dropdown
    user_meeting_ids = UserMeetingDB.get_meetings_for_user(user)
    meetings_with_titles = [(mid, MeetingDB.getMeetingTitle(mid)) for mid in user_meeting_ids]


    return render_template(
        'dashboard.html',
        username=user_id,
        totalCount=totalCount,
        joinCount=joinCount,
        hostCount=hostCount,
        createdMeetings=created_with_members,
        joinedMeeting=joined_with_members,tuple_meetings=tuple_meetings,
        assigned_to_me=assigned_to_me,
        assigned_by_me=assigned_by_me,
        meetings=meetings_with_titles,
        selected_status=filter_status,
        selected_meeting=filter_meeting_id,
        now=datetime.now()
    )



from werkzeug.utils import secure_filename
import os

@app.route('/task/<int:task_id>/complete', methods=['POST'])
@login_required
def mark_task_done(task_id):
    task = TaskDB.get_task_by_id(task_id)
    if not task:
        return "<h1>Task not found</h1>"

    if task['assignedTo'] != session['username']:
        return "<h1>Unauthorized</h1>"
    task_name=task["taskName"]
    meeting_id=MeetingDB.getMeetingTitle(task["meetingId"])
    
    try:
        
        load_dotenv()
        sender_email = os.environ.get('APP_EMAIL')
        app_password = os.environ.get('APP_EMAIL_CODE')
        receiver_email = UserDB.get_email(TaskDB.get_hosted_by(task_id))
        
        # receiver_email = UserDB.get_email(task['assignedBy'])
        uploaded_file = request.files.get('file')

        if uploaded_file and uploaded_file.filename != '':
            # ✅ Save file temporarily
            filename = secure_filename(uploaded_file.filename)
            upload_folder = "uploads"
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            uploaded_file.save(file_path)

            # ✅ Send file via email
            send_assignment_email(
                sender_email=sender_email,
                sender_app_password=app_password,
                receiver_email=receiver_email,
                subject=f"Assignment Completed by {session['username']}",
                body = f"The task '{task_name}' assigned to {session['username']} under Meeting ID {meeting_id} has been successfully completed.",
                file_path=file_path
            )

            # Optional: remove the file after sending
            os.remove(file_path)

        else:
            # No file uploaded, just send a text message
            send_message_email(
                sender_email=sender_email,
                sender_app_password=app_password,
                receiver_email=receiver_email,
                subject="Assignment Completion",
                body = f"The task '{task_name}' assigned to {session['username']} under Meeting ID {meeting_id} has been successfully completed."
            )
            print(sender_email, app_password, receiver_email)
    except Exception as e:
        import json
        data = {"status": "error", "message": "Invalid input"}
        print(data)
        print(sender_email, app_password, receiver_email)
        return redirect(url_for('dashboard'))    # Need fixing
    else:
        TaskDB.mark_done(task_id, done=True)
        
    return redirect(url_for('dashboard'))
        
    





#------------------ work with multiple rooms creation --------------------#
@app.route('/meeting_create',methods=['POST','GET'])
@login_required
def meeting_create():
    if request.method=='POST':
        title=request.form['title']
        description=request.form['description']
        host=session['username']
        meetingId = meeting_id_create()
        passkey = meeting_pass_key()
        MeetingDB.add_meeting(meeting_id=meetingId, passkey=passkey, host=host, co_host=None, meetingTitle=title, meetingDescription=description)
        
        
        
        
        UserMeetingDB.add_user_to_meeting(host,meetingId,1,0,None,None,None)
        
        members=UserMeetingDB.get_users_for_meeting(meetingId)
        AES_generate_and_encrypt_keys(meetingId,os.path.join(os.path.dirname(__file__), "keys"))
        
        
        
        e2e=E2E()
        e2e.create_AES_keys_for_users(UserMeetingDB.get_users_for_meeting(meetingId),meetingId)
        e2e.set_Aes_key(meetingId)
        
        
        return redirect(url_for('dashboard'))
    return render_template('create_meeting.html')




# meetingId=meetingId,
#                            passkey=real_passkey,
#                            host=real_host,
#                            chat_history=chat_history,
#                            current_user=session['username'],meetingTitle=meetingTitle,meetingDescription=meetingDescription




@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop("private_key",None)
    return redirect(url_for('login'))


@app.route('/access_denined')
@login_required
def blocked():
    return render_template('blocked.html')

@app.route('/join_meeting', methods=['GET', 'POST'])
@login_required
def join_meeting():
    username = session['username']
    
    if request.method == 'POST':
        session_id = request.form['session_id']
        passkey = request.form['passkey']
        
        if MeetingDB.get_passkey(session_id) == passkey:
            if username not in UserMeetingDB.get_users_for_meeting(session_id):
                UserMeetingDB.add_user_to_meeting(username, session_id, 1, 0, None, None, None)

                e2e = E2E()
                e2e.format_key(session_id, UserMeetingDB.get_users_for_meeting(session_id))

            return redirect(f'/meeting/{session_id}')
        else:
            return render_template('join_room.html', success=False, message="Invalid passkey or session ID.")

    # GET request
    meeting = request.args.get('meeting')
    if meeting:
        host = MeetingDB.get_host(meeting)
        if UserMeetingDB.get_is_blocked(username, meeting) or \
           UserMeetingDB.get_difi_key(host, meeting) != UserMeetingDB.get_difi_key(username, meeting):
            return render_template('blocked.html')

        if username in UserMeetingDB.get_users_for_meeting(meeting):
            return redirect(f'/meeting/{meeting}')
    
    return render_template('join_room.html', meeting=meeting)


@app.route('/join_meeting/<meetingId>/<passkey>', methods=["GET", "POST"])
@login_required
def join_meeting_using_link(meetingId, passkey):
    username = session['username']

    if request.method == 'POST':
        session_id = request.form['session_id']
        passkey_input = request.form['passkey']
        
        if MeetingDB.get_passkey(session_id) == passkey_input:
            if username not in UserMeetingDB.get_users_for_meeting(session_id):
                UserMeetingDB.add_user_to_meeting(username, session_id, 1, 0, None, None, None)

                e2e = E2E()
                e2e.format_key(session_id, UserMeetingDB.get_users_for_meeting(session_id))

            return redirect(f'/meeting/{session_id}')
        else:
            return render_template('join_room.html', success=False, message="Invalid passkey or session ID.")

    # GET request: attempt direct access via link
    if MeetingDB.get_passkey(meetingId) == passkey:
        if username not in UserMeetingDB.get_users_for_meeting(meetingId):
            UserMeetingDB.add_user_to_meeting(username, meetingId, 1, 0, None, None, None)

            e2e = E2E()
            e2e.format_key(meetingId, UserMeetingDB.get_users_for_meeting(meetingId))

        return redirect(f'/meeting/{meetingId}')
    else:
        return render_template("join_room.html", meetingId=meetingId, passkey=passkey, success=False, message="Invalid passkey.")


# ----------------------- linked with home ----------------
@app.route('/meeting/<meetingId>')    
@login_required
def meeting(meetingId):
    logged_in_user = session.get('username')

    real_passkey = MeetingDB.get_passkey(meetingId)
    real_host = MeetingDB.get_host(meetingId)

    if logged_in_user != real_host:
        if logged_in_user not in UserMeetingDB.get_users_for_meeting(meetingId) and logged_in_user != UserMeetingDB.get_is_blocked(logged_in_user,meetingId):
            return redirect(url_for('join_meeting', message="Access Denied."))

    e2e=E2E()
    #AES_decrypt_message(symmetric_key,chat_history[i][1])
    from datetime import datetime
    MONTH_ABBR = {
        "01": "Jan", "02": "Feb", "03": "Mar", "04": "Apr",
        "05": "May", "06": "Jun", "07": "Jul", "08": "Aug",
        "09": "Sep", "10": "Oct", "11": "Nov", "12": "Dec"
    }
    chat_history = MessageDB.get_messages(meetingId)
    for i in range(len(chat_history)):
        raw_day, raw_month = chat_history[i][3].split(":")  # "03:07" -> "03", "07"
        formatted_date = f"{int(raw_day)} {MONTH_ABBR[raw_month]}"
        # "3 Jul"
        
        chat_history[i] = {
            'username': chat_history[i][0],
            'message': e2e.decrypt(chat_history[i][1], meetingId).decode(),
            'time': chat_history[i][2],
            'date': formatted_date,
            'id': chat_history[i][4]
        }
        

    meetingTitle=MeetingDB.getMeetingTitle(meeting_id=meetingId)
    meetingDescription=MeetingDB.getMeetingDescription(meeting_id=meetingId)
    members=UserMeetingDB.get_users_for_meeting(meetingId)
    co_host=MeetingDB.get_co_host(meetingId)
    tuple_meetings=[]
    
    meetings = UserMeetingDB.get_meetings_for_user(user_id=logged_in_user)
    for i in meetings:
        temp=(MeetingDB.getMeetingTitle(i),MeetingDB.get_host(i),i)
        tuple_meetings.append(temp)
    return render_template("meeting.html", 
                           meetingId=meetingId,
                           passkey=real_passkey,
                           host=real_host,
                           chat_history=chat_history,
                           current_user=session['username'],meetingTitle=meetingTitle,meetingDescription=meetingDescription,members=members,co_host=co_host,tuple_meetings=tuple_meetings)



from flask import jsonify





@app.route('/get_blocked_users')
def get_blocked_users():
    meeting_id = request.args.get('room')

    if not meeting_id:
        return jsonify({"error": "Missing meeting ID"}), 400

    blocked_users = [
        row['userId']
        for row in UserMeetingDB.get_blocked_users()
        if row['meetingId'] == meeting_id
    ]
    return jsonify(blocked_users)



@app.route('/get_users')
def get_users():
    meeting_id = request.args.get('room')
    if not meeting_id:
        return jsonify([])

    # Get all users who are not blocked in this meeting
    all_users = UserMeetingDB.get_users_for_meeting(meeting_id)
    unblocked_users = [
        
        user for user in all_users
        if not UserMeetingDB.get_is_blocked(user, meeting_id)
    ]

    return jsonify(unblocked_users)




#------------------- send the user to the associated meeting------------------













#-------------------------------todo work----------------

@app.route('/delete_todo/<int:task_id>', methods=['GET', 'POST'])
@login_required
def delete_todo(task_id):
    task = TaskDB.get_task_by_id(task_id)
    if not task:
        return "<h1>Task not found</h1>"


    TaskDB.delete_task(task_id)
    return redirect(request.referrer or url_for('dashboard'))  # Redirect back to TODO list
@app.route('/update_deadline/<int:task_id>', methods=['GET'])
@login_required
def show_update_deadline_form(task_id):
    task = TaskDB.get_task_by_id(task_id)
    if not task:
        return "<h1>Task not found</h1>"
    
    if task['hostedBy'] != session['username']:
        return "<h1>Unauthorized</h1>"
    
    return render_template('update_deadline.html', task=task)
@app.route('/update_deadline/<int:task_id>', methods=['POST'])
@login_required
def update_deadline(task_id):
    new_deadline_raw = request.form.get('deadline')  # '2025-07-01T14:00'
    try:
        new_deadline = datetime.strptime(new_deadline_raw, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "<h1>Invalid datetime format</h1>"

    TaskDB.update_deadline(task_id, new_deadline)
    return redirect(url_for('show_todo', meetingId=TaskDB.get_task_by_id(task_id)['meetingId']))




























    

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True) #nosec B201



