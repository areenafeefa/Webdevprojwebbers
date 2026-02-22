# imports
import sqlite3
import requests
import json
from flask import Flask, render_template, session, redirect, url_for, request, g, flash, jsonify
from flask_socketio import SocketIO, emit, join_room

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import date, datetime, timedelta, time, timezone
import os
from urllib.parse import quote
import re
from markupsafe import Markup, escape
from helpers import *
# make these functions available in all templates

# --- App Setup ---
app = Flask(__name__)
DATABASE = 'database.db'
app.secret_key = 'Secret'

# Upload folder configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Initialize Socket.IO
socketio = SocketIO(app, manage_session=False,  cors_allowed_origins="*")
app.jinja_env.filters['mention'] = mention

# Dictionary to track online users: username -> sid
online_users = {}

song_game_state = {}
# Connect to your DB
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
# --- Inject login info and globals to all templates ---
@app.context_processor
def inject_globals():
    conn = get_db()
    
    # Global communities (all communities)
    global_communities = conn.execute("SELECT * FROM communities ORDER BY name").fetchall()
    
    # User communities (only the ones the logged-in user belongs to)
    user_communities = []
    if 'user_id' in session:
        user_communities = conn.execute("""
            SELECT c.community_id, c.name
            FROM communities c
            JOIN community_members cm ON c.community_id = cm.community_id
            WHERE cm.user_id = ?
            ORDER BY c.name
        """, (session['user_id'],)).fetchall()

    if 'user_id' in session:
        notifications = conn.execute("""
            SELECT n.*, u.username AS actor_username
            FROM notifications n
            LEFT JOIN users u ON n.actor_id = u.user_id
            WHERE n.user_id = ?
            ORDER BY n.created_at DESC
            LIMIT 5
        """, (session['user_id'],)).fetchall()

        unread_count = conn.execute("""
            SELECT COUNT(*) as count
            FROM notifications
            WHERE user_id = ? AND is_read = 0
        """, (session['user_id'],)).fetchone()['count']
    else:
        notifications = []
        unread_count = 0
        

    
    return dict(
        global_communities=global_communities,
        user_communities=user_communities,
        logged_in='username' in session,
        username=session.get('username'),
        notifications=notifications,
        unread_count=unread_count)
@app.context_processor
def inject_user_profile_pic():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute("""
            SELECT profile_pic FROM user_profiles WHERE user_id = ?
        """, (session['user_id'],)).fetchone()
        
        if user and user['profile_pic']:
            # Wrap the DB path in url_for so it works in the browser
            profile_pic = url_for('static', filename=user['profile_pic'])
        else:
            profile_pic = url_for('static', filename='img.png')  # default fallback
        
        return dict(current_user_profile_pic=profile_pic)
    
    # fallback if not logged in
    return dict(current_user_profile_pic=url_for('static', filename='img.png'))

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite3_db'):
        g.sqlite3_db.close()

def get_local_timestamp():
    """FIX #8: Singapore time (UTC+8)"""
    from datetime import datetime, timezone, timedelta
    utc_now = datetime.now(timezone.utc)
    singapore_time = utc_now + timedelta(hours=8)
    return singapore_time.strftime('%Y-%m-%d %H:%M:%S')


# --- Routes ---
# Home page
@app.route('/api/users')
def api_users():
    if 'username' not in session:
        return {'users': []}, 401

    conn = get_db()
    # 1. Get current_user_id manually since get_user_id() is missing
    user_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()
    
    if not user_row:
        return {'users': []}, 401
    
    current_user_id = user_row['user_id']
    
    # 2. Proceed with fetching other users
    users = conn.execute("""
        SELECT u.user_id, u.username, p.display_name
        FROM users u
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.user_id != ?
        ORDER BY p.display_name
    """, (current_user_id,)).fetchall()

    user_list = [
        {'user_id': u['user_id'], 'username': u['username'], 'display_name': u['display_name'] or u['username']}
        for u in users
    ]
    return {'users': user_list}

app.jinja_env.globals.update(
    count_unread_notifications=count_unread_notifications,
    get_notifications=get_notifications
)

@app.route('/')
def index():
    conn = get_db()

    # 1️⃣ [ORIGINAL] Get user_id safely and heal session if needed
    user_id = session.get('user_id')
    current_user = None
    if not user_id and 'username' in session:
        user_row = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", 
            (session['username'],)
        ).fetchone()
        if user_row:
            user_id = user_row['user_id']
            session['user_id'] = user_id

    # 2️⃣ [ORIGINAL] Fetch Current User Info (Moved up so we can use it)
    if user_id:
        user_row = conn.execute("""
            SELECT u.user_id, u.username, COALESCE(p.display_name, u.username) AS display_name
            FROM users u
            LEFT JOIN user_profiles p ON u.user_id = p.user_id
            WHERE u.user_id = ?
        """, (user_id,)).fetchone()

        if user_row:
            current_user = dict(user_row)

# 3️⃣ [UPDATED] DAILY PROMPT LOGIC (With UTC 00:00 Fix)
    today_str = date.today().isoformat()
    
    existing_prompt = conn.execute("""
        SELECT 1 FROM posts 
        WHERE post_type = 'daily_prompt' 
        AND date(created_at) = ?
    """, (today_str,)).fetchone()

    # Only create if missing AND user is logged in
    if not existing_prompt and user_id:
        import random
        # Ensure we have the right datetime imports here locally if not global
        from datetime import datetime, timezone 
        
        prompt_options = [
            "What is a small win you had today?",
            "What is your favorite comfort food?",
            "Share a photo of something blue near you.",
            "What is the best advice you've ever received?",
            "If you could travel anywhere right now, where would you go?",
            "What was the last song you listened to?",
            "What are you grateful for today?"
        ]
        new_question = random.choice(prompt_options)
        
        # Find a valid Community ID (fallback to 1 or create 'General')
                # FIXED: Always use "General" community for daily prompts
        comm_row = conn.execute("""
            SELECT community_id FROM communities 
            WHERE name = 'General' 
            LIMIT 1
        """).fetchone()
        
        if comm_row:
            target_cid = comm_row['community_id']
        else:
            # Create "General" community if it doesn't exist
            cursor = conn.execute("""
                INSERT INTO communities (name, description) 
                VALUES (?, ?)
            """, ('General', 'General discussion'))
            conn.commit()
            target_cid = cursor.lastrowid

        # --- FIX: Force timestamp to UTC 00:00:00 ---
        utc_midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        conn.execute("""
            INSERT INTO posts (user_id, community_id, title, content, post_type, created_at)
            VALUES (?, ?, 'Daily Prompt', ?, 'daily_prompt', ?)
        """, (user_id, target_cid, new_question, utc_midnight)) 
        conn.commit()

    # 4️⃣ [ORIGINAL] Fetch Main Feed (Now includes the new Daily Prompt!)
    posts = conn.execute("""
        SELECT 
            posts.*, 
            users.username, 
            communities.name AS community_name,
            (SELECT COUNT(*) FROM post_likes WHERE post_id = posts.post_id) AS like_count,
            (SELECT 1 FROM post_likes WHERE post_id = posts.post_id AND user_id = ?) AS user_liked
            FROM posts
            JOIN users ON posts.user_id = users.user_id
            JOIN communities ON posts.community_id = communities.community_id
            WHERE 
                (post_type = 'daily_prompt' AND date(posts.created_at) = date('now'))
                OR post_type != 'daily_prompt'
            ORDER BY 
                CASE WHEN post_type = 'daily_prompt' THEN 1 ELSE 0 END DESC,
                posts.created_at DESC
    """, (user_id,)).fetchall()

    # 5️⃣ [ORIGINAL] Get sidebar data
    sidebar_data = get_home_sidebar_data(user_id, top_n_communities=3, recent_posts_limit=5)

    # 6️⃣ [ORIGINAL] Render template
    return render_template(
        'index.html',
        posts=posts,
        current_user=current_user,
        **sidebar_data
    )
    
# 
#  Community page
@app.route('/community/<int:community_id>')
def community(community_id):
    conn = get_db()
    current_user_id = session.get('user_id')
    is_member = False

    # 1️⃣ Self-heal session
    if not current_user_id and 'username' in session:
        user_row = conn.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (session['username'],)
        ).fetchone()

        if user_row:
            current_user_id = user_row['user_id']
            session['user_id'] = current_user_id

    # 2️⃣ Check membership
    if current_user_id:
        is_member = conn.execute(
            "SELECT 1 FROM community_members WHERE user_id = ? AND community_id = ?",
            (current_user_id, community_id)
        ).fetchone() is not None

    # 3️⃣ Get community details
    community_row = conn.execute(
        "SELECT * FROM communities WHERE community_id = ?",
        (community_id,)
    ).fetchone()

    if not community_row:
        return "Community not found", 404

    # 4️⃣ Fetch posts
    posts = conn.execute("""
        SELECT p.*, u.username,
               (SELECT COUNT(*) FROM post_likes WHERE post_id = p.post_id) AS like_count,
               (SELECT 1 FROM post_likes 
                WHERE post_id = p.post_id AND user_id = ?) AS user_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id 
        WHERE p.community_id = ?
        ORDER BY p.created_at DESC
    """, (current_user_id, community_id)).fetchall()


    # 5️⃣ Get sidebar data from helper
    sidebar_data = get_community_sidebar_data(current_user_id, community_id)

    return render_template(
        'community.html',
        posts=posts,
        is_member=is_member,
        **sidebar_data   # injects community, community_friends, community_members_count
    )



import time # Ensure this is at the top with your other imports

# --- View Post + Comments (AJAX Integrated) ---
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def openpost(post_id):
    conn = get_db()
    current_user = get_current_user(conn)
    user_id = session.get('user_id')

    post = fetch_post(conn, post_id)
    if not post:
        return "Post not found.", 404

    # --- Handle Comment/Event Submission ---
    if request.method == "POST":
        if not current_user:
            return redirect(url_for("login"))

        # Register
        if handle_event_registration(conn, post, current_user):
            return redirect(url_for("openpost", post_id=post_id))

        # Unregister
        if handle_event_unregistration(conn, post, current_user):
            return redirect(url_for("openpost", post_id=post_id))

        # Comments
        if handle_comment_submission(conn, post, current_user):
            return redirect(url_for("openpost", post_id=post_id))

    # --- VIEW RESTRICTION LOGIC ---
    # 1. Fetch all comments first
    comments = fetch_comments(get_db(), post_id, user_id)
    
    # 2. Check if user has commented
    user_has_commented = False
    if user_id:
        for c in comments:
            if c['user_id'] == user_id: 
                user_has_commented = True
                break
    
    # 3. Apply Restriction
    # If it is a daily prompt AND user hasn't commented...
    locked_view = False
    if post['post_type'] == 'daily_prompt' and not user_has_commented:
        locked_view = True
        # Only show the top 2 comments as a teaser
        comments = []

    is_registered = check_event_registration(conn, post, current_user)

    return render_template(
        "openpost.html",
        post=post,
        comments=comments,
        is_registered=is_registered,
        locked_view=locked_view # Pass this flag to HTML
    )
    
@app.route('/create_post', methods=['GET', 'POST'])

@app.route('/create_post/<int:community_id>', methods=['GET', 'POST'])
def create_post(community_id=None):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    user = conn.execute(
        "SELECT user_id FROM users WHERE username = ?",
        (session['username'],)
    ).fetchone()

    if not user:
        return redirect(url_for('login'))

    user_id = user['user_id']

    community_name = None
    if community_id:
        comm = conn.execute(
            "SELECT name FROM communities WHERE community_id = ?",
            (community_id,)
        ).fetchone()
        community_name = comm['name'] if comm else None

    communities = [] if community_id else conn.execute(
        "SELECT * FROM communities"
    ).fetchall()

    if request.method == 'POST':

        title = request.form.get('title')
        content = request.form.get('content')
        post_type = request.form.get('post_type', 'general')

        cid = community_id if community_id else request.form.get('community_id')

        if not cid:
            flash("Community is required.")
            return redirect(request.url)

        # --- Image Handling ---
        file = request.files.get('image')
        image_url = None

        if file and allowed_file(file.filename):
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"image_{int(time.time())}.{ext}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = url_for('static', filename='uploads/' + filename)

        # --- Insert Post (WITH post_type FIXED) ---
        conn.execute("""
            INSERT INTO posts (user_id, community_id, title, content, image_url, post_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, cid, title, content, image_url, post_type))

        conn.commit()

        new_post_id = conn.execute(
            "SELECT last_insert_rowid() AS id"
        ).fetchone()['id']

        # Notify mentions in post content
        link = url_for('openpost', post_id=new_post_id)
        notify_mentions(content, user_id, link, new_post_id)

        # --- Event Handling ---
        if post_type == 'event':

            location = request.form.get('location')
            event_date = request.form.get('event_date')
            event_time = request.form.get('event_time')

            if not location or not event_date or not event_time:
                flash("All event fields are required.")
                return redirect(request.url)

            conn.execute("""
                INSERT INTO event_posts (post_id, organiser_id, location, event_date, event_time)
                VALUES (?, ?, ?, ?, ?)
            """, (new_post_id, user_id, location, event_date, event_time))

            conn.commit()

        return redirect(url_for('openpost', post_id=new_post_id))

    return render_template(
        'create_post.html',
        communities=communities,
        community_name=community_name,
        community_id=community_id
    )
@app.route("/interests", methods=["GET", "POST"])
def interests():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        # Get checkbox interests
        checkbox_interests = [
            i.strip().lower()
            for i in request.form.getlist("interests[]")
            if i.strip()
        ]

        # Get custom interests
        custom_input = request.form.get("custom_interests", "").strip()
        custom_interests = [
            i.strip().lower()
            for i in custom_input.split(",")
            if i.strip()
        ] if custom_input else []

        all_interests = set(checkbox_interests + custom_interests)

        conn = get_db()
        for interest in all_interests:
            try:
                conn.execute(
                    "INSERT INTO user_interests (user_id, interest) VALUES (?, ?)",
                    (user_id, interest)
                )
            except sqlite3.IntegrityError:
                pass

        conn.commit()
        return redirect(url_for("index"))

    # If GET request, render the interests form
    return render_template("interests.html")

#delete posts
@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    # 1. Security Check: Must be logged in
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    conn = get_db()
    
    # 2. Verify Ownership: Check if the post exists and belongs to the user
    query = '''
        SELECT u.username 
        FROM posts p
        JOIN users u ON p.user_id = u.user_id 
        WHERE p.post_id = ?
    '''
    post = conn.execute(query, (post_id,)).fetchone()

    if not post:
        return jsonify({'status': 'error', 'message': 'Post not found'}), 404

    if post['username'] != session['username']:
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    try:
        # --- HIERARCHICAL CLEANUP (Bottom-Up Deletion) ---
        
        # B. Delete all Comments on this post
        # This removes them from the post view AND the user's profile
        conn.execute('DELETE FROM comments WHERE post_id = ?', (post_id,))
        
        # C. Delete all Likes on the post itself
        conn.execute('DELETE FROM post_likes WHERE post_id = ?', (post_id,))
        
        # D. Delete the actual Post
        conn.execute('DELETE FROM posts WHERE post_id = ?', (post_id,))
        
        # Finalize the transaction
        conn.commit()
        return jsonify({'status': 'success'})

    except Exception as e:
        # If any step fails, roll back everything to keep data consistent
        conn.rollback()
        return jsonify({'status': 'error', 'message': f"Database error: {str(e)}"}), 500


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    conn = get_db()
    
    # Get comment and verify ownership
    comment = conn.execute("""
        SELECT c.comment_id, u.username 
        FROM comments c
        JOIN users u ON c.user_id = u.user_id
        WHERE c.comment_id = ?
    """, (comment_id,)).fetchone()

    if not comment:
        return jsonify({'status': 'error', 'message': 'Comment not found'}), 404

    if comment['username'] != session['username']:
        return jsonify({'status': 'error', 'message': 'Permission denied'}), 403

    try:
        # Delete likes first (handle case where comment_likes table is malformed)
        try:
            conn.execute('DELETE FROM comment_likes WHERE comment_id = ?', (comment_id,))
        except sqlite3.OperationalError:
            # Ignore "no such column: comment_id" error if the table schema is wrong
            pass
            
        # Delete comment
        conn.execute('DELETE FROM comments WHERE comment_id = ?', (comment_id,))
        conn.commit()
        return jsonify({'status': 'success'})

    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    conn = get_db()
    
    # helper.py function to handle insertion
    # We can reuse handle_comment_submission but we need it to return the new comment ID/data
    # Or we can just write the insert here for simplicity and JSON return
    
    content = request.json.get('content') if request.is_json else request.form.get('content')
    content = content.strip() if content else ""
    
    if not content:
        return jsonify({'status': 'error', 'message': 'Comment cannot be empty'}), 400

    user_row = conn.execute("SELECT user_id, username FROM users WHERE username = ?", (session['username'],)).fetchone()
    user_id = user_row['user_id']
    username = user_row['username']

    try:
        cursor = conn.execute(
            "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
            (post_id, user_id, content)
        )
        new_comment_id = cursor.lastrowid
        conn.commit()
        
        # Get the created timestamp
        comment_row = conn.execute("SELECT created_at FROM comments WHERE comment_id = ?", (new_comment_id,)).fetchone()
        created_at = comment_row['created_at']
        
        # Notify owner (optional, reused logic if possible, or just duplicate for now to be safe)
        post = fetch_post(conn, post_id)
        if post:
            notify_post_owner(post, {'user_id': user_id, 'username': username})
            
            # Notify mentions in comment content
            link = url_for('openpost', post_id=post_id)
            notify_mentions(content, user_id, link, post_id)

        formatted_content = str(mention(content))
        return jsonify({
            'status': 'success',
            'comment_id': new_comment_id,
            'content': content,
            'formatted_content': formatted_content,
            'username': username,
            'created_at': created_at
        })

    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# --- Integrated AJAX Likes (No Refresh) ---
@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'username' not in session:
        return {"error": "Unauthorized"}, 401
    
    conn = get_db()
    user_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()
    if not user_row:
        return {"error": "User not found"}, 404
    
    user_id = user_row['user_id']
    
    # Check if like exists
    existing = conn.execute("SELECT 1 FROM post_likes WHERE user_id=? AND post_id=?", 
                            (user_id, post_id)).fetchone()
    
    if existing:
        conn.execute("DELETE FROM post_likes WHERE user_id=? AND post_id=?", (user_id, post_id))
        liked = False
    else:
        conn.execute("INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)", (user_id, post_id))
        liked = True
    
    conn.commit()
    
    # Get the updated count
    count_row = conn.execute("SELECT COUNT(*) as count FROM post_likes WHERE post_id=?", (post_id,)).fetchone()
    new_count = count_row['count']
   
    post = conn.execute("""
            SELECT user_id FROM posts WHERE post_id = ?
        """, (post_id,)).fetchone()
    
    if post and post['user_id'] != user_id:
            create_notification(
                user_id=post['user_id'],
                actor_id=user_id,
                notif_type="post_like",
                message=f"{session['username']} liked your post",
                link=url_for('openpost', post_id=post_id),
                reference_id=post_id
            )
    return {
        "status": "success",
        "liked": liked,
        "new_count": new_count,
        "post_id": post_id
    }

#like comments
@app.route('/like_comment/<int:comment_id>', methods=['POST'])
def like_comment(comment_id):
    if 'user_id' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    conn = get_db()
    user_id = session.get('user_id')
    
    try:
        # Check if the user already liked this comment
        existing = conn.execute(
            "SELECT 1 FROM comment_likes WHERE user_id = ? AND comment_id = ?", 
            (user_id, comment_id)
        ).fetchone()
        
        if existing:
            # Unlike: Remove the record
            conn.execute(
                "DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?", 
                (user_id, comment_id)
            )
            liked = False
        else:
            # Like: Insert new record
            conn.execute(
                "INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)", 
                (user_id, comment_id)
            )
            liked = True
            
        conn.commit()
        
        # Get new count
        count_row = conn.execute(
            "SELECT COUNT(*) as count FROM comment_likes WHERE comment_id = ?", 
            (comment_id,)
        ).fetchone()
        new_count = count_row['count']
        
        return jsonify({
            "status": "success",
            "liked": liked,
            "new_count": new_count,
            "comment_id": comment_id
        })
        
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500 

def mention_to_link(text):
    if not text:
        return ""

    # This regex finds @ followed by alphanumeric characters/underscores
    # It stops at punctuation or spaces automatically
    mention_pattern = r'@(\w+)'

    def replace_with_link(match):
        clean_username = match.group(1)
        
        # We still check the DB, but Regex ensures we only check actual "usernames"
        conn = get_db()
        user_exists = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (clean_username,)
        ).fetchone()

        if user_exists:
            link = url_for('userprofile', username=clean_username)
            # Returning the HTML link
            return f'<a href="{link}" class="text-primary text-decoration-none fw-bold">@{clean_username}</a>'
        
        # If user doesn't exist, return the original text (@whatever)
        return f'@{clean_username}'

    # re.sub handles the entire string, including newlines and complex spacing
    return re.sub(mention_pattern, replace_with_link, text)

app.jinja_env.filters['mention'] = mention_to_link

@app.route("/register", methods=["POST"])
def register():
    # Extract form fields
    username = request.form.get("username")
    age = request.form.get("age")
    phone = request.form.get("phone")
    email = request.form.get("email")
    password = request.form.get("password")

    # Basic validation
    if not all([username, age, phone, email, password]):
        flash("All fields are required", "register_error")
        return redirect(url_for("index"))

    if not age.isdigit() or int(age) < 13:
        flash("Age must be a valid number (13+)", "register_error")
        return redirect(url_for("index"))

    conn = get_db()
    try:
        # Hash password
        hashed_pw = generate_password_hash(password)

        # Insert into users table
        conn.execute(
            "INSERT INTO users (username, age, phone, email, password) VALUES (?, ?, ?, ?, ?)",
            (username, int(age), phone, email, hashed_pw)
        )

        # Optional: create user profile
        user_id = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        ).fetchone()["user_id"]

        conn.execute(
            "INSERT INTO user_profiles (user_id, display_name, bio) VALUES (?, ?, ?)",
            (user_id, username, "")
        )

        conn.commit()

        # Log user in automatically
        session["username"] = username
        session["logged_in"] = True
        session["user_id"] = user_id

        flash("Registration successful!", "success")
        return redirect(url_for("interests"))

    except sqlite3.IntegrityError:
        # Trigger modal with flash
        flash("Username or email already exists", "register_error")
        return redirect(url_for("interests"))
    
# Login
@app.route("/login", methods=["GET","POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        # Username doesn't exist
        flash("Login to access communications", "login_error")
        return redirect(url_for("index"))

    if not check_password_hash(user["password"], password):
        # Username exists but password is wrong
        flash("Wrong username/password", "login_error")
        return redirect(url_for("index"))

    # 1. Wipe any old session data
    session.clear() 

    # 2. Set the fresh user identity
    session["username"] = user["username"]
    session["user_id"] = user["user_id"]  
    session["logged_in"] = True

    return redirect(url_for("index"))



# Logout
@app.route('/logout')
def logout():
    session.clear()  # This deletes EVERYTHING in the session
    return redirect(url_for('index'))

@app.route('/userprofile/<username>')
def userprofile(username):
    conn = get_db()

    # 1. Get the ID of the person CURRENTLY logged in (to check for likes and friendship)
    viewer_id = session.get('user_id', 0) 

    # --- Profile info (include profile_pic) ---
    profile = conn.execute("""
        SELECT u.user_id, u.username, u.email, u.phone, u.age,
               p.display_name, p.bio, p.profile_pic
        FROM users u
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.username = ?
    """, (username,)).fetchone()

    if not profile:
        return "Profile not found", 404

    profile_owner_id = profile['user_id']

    # --- Communities ---
    user_communities = conn.execute("""
        SELECT c.community_id, c.name, c.description
        FROM community_members cm
        JOIN communities c ON cm.community_id = c.community_id
        WHERE cm.user_id = ?
        ORDER BY c.name
    """, (profile_owner_id,)).fetchall()

    # --- Posts by user ---
    posts = conn.execute("""
        SELECT p.post_id, p.title, p.content, p.created_at, 
               p.image_url AS image_path,
               c.community_id, c.name AS community_name,
               u.username,
               (SELECT COUNT(*) FROM post_likes WHERE post_id = p.post_id) AS like_count,
               (SELECT 1 FROM post_likes WHERE post_id = p.post_id AND user_id = ?) AS user_liked
        FROM posts p
        JOIN communities c ON p.community_id = c.community_id
        JOIN users u ON p.user_id = u.user_id
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
    """, (viewer_id, profile_owner_id)).fetchall() 

    # --- Comments by user ---
    comments = conn.execute("""
        SELECT cm.comment_id, cm.content, cm.created_at,
               p.post_id, p.title AS post_title,
               c.community_id, c.name AS community_name,
               u.username,
               (SELECT COUNT(*) FROM comment_likes WHERE comment_id = cm.comment_id) AS like_count,
               (SELECT 1 FROM comment_likes WHERE comment_id = cm.comment_id AND user_id = ?) AS user_liked
        FROM comments cm
        JOIN posts p ON cm.post_id = p.post_id
        JOIN communities c ON p.community_id = c.community_id
        JOIN users u ON cm.user_id = u.user_id
        WHERE cm.user_id = ?
        ORDER BY cm.created_at DESC
    """, (viewer_id, profile_owner_id)).fetchall()

    # --- Friendship info ---
    friendship = conn.execute("""
        SELECT *
        FROM friends
        WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)
    """, (viewer_id, profile_owner_id, profile_owner_id, viewer_id)).fetchone()

    return render_template(
        'userprofile.html',
        profile=profile,
        communities=user_communities,
        posts=posts,
        comments=comments,
        friendship=friendship  # pass it to template
    )

# idk reddit thing to avoid some error i copy pasted never removed js keep it idk mayve its holding everyt together
@app.route("/favicon.ico")
def favicon():
    return "", 200

# Create community
@app.route('/create_community', methods=['GET', 'POST'])
def create_community():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name').strip()
        description = request.form.get('description').strip()
        if not name:
            return "Community name is required."
        conn = get_db()
        existing = conn.execute("SELECT * FROM communities WHERE name = ?", (name,)).fetchone()
        if existing:
            return "Community already exists."
        conn.execute("INSERT INTO communities (name, description) VALUES (?, ?)", (name, description))
        conn.commit()
        community_id = conn.execute("SELECT community_id FROM communities WHERE name = ?", (name,)).fetchone()['community_id']
        return redirect(url_for('community', community_id=community_id))
    return render_template('create_community.html')

# --- chat ---
@app.route('/chat/<username>', methods=['GET', 'POST'])
def chat(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']

    other_user = None
    current_group = None
    messages = []
    
    # Check if it is a group chat
    if username.startswith('group_'):
        group_id = username.split('_')[1]
        current_group = conn.execute("SELECT * FROM group_chats WHERE group_id=?", (group_id,)).fetchone()
        
        if not current_group:
            return "Group not found", 404
            
        current_group = dict(current_group)
        
        # New Message (Group)
        if request.method == 'POST':
            content = request.form.get('content')
            if content:
                conn.execute(
                    "INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)",
                    (group_id, current_user_id, content)
                )
                conn.commit()
            return redirect(url_for('chat', username=username))

        # Fetch Group Messages
        messages = conn.execute("""
            SELECT m.message_id, m.content, m.created_at, u.username AS sender_username, COALESCE(p.display_name, u.username) as display_name
            FROM group_messages m
            JOIN users u ON m.sender_id = u.user_id
            LEFT JOIN user_profiles p ON u.user_id = p.user_id
            WHERE m.group_id = ?
            ORDER BY m.created_at ASC
        """, (group_id,)).fetchall()

        # Fetch Group Members (for Info Modal)
        members = conn.execute("""
            SELECT u.username, COALESCE(p.display_name, u.username) as display_name, u.user_id
            FROM group_members gm
            JOIN users u ON gm.user_id = u.user_id
            LEFT JOIN user_profiles p ON u.user_id = p.user_id
            WHERE gm.group_id = ?
        """, (group_id,)).fetchall()
        current_group['members'] = [dict(m) for m in members]

    else:
        # Direct Message Logic
        other_user = conn.execute("""
            SELECT u.user_id, u.username, COALESCE(p.display_name, u.username) as display_name, u.email, u.phone, u.age, p.bio
            FROM users u
            LEFT JOIN user_profiles p ON u.user_id=p.user_id
            WHERE u.username=?
        """, (username,)).fetchone()
        
        if not other_user:
            return "User not found"

        # Enforce Friendship
        friendship = conn.execute("""
            SELECT status FROM friends 
            WHERE (requester_id=? AND addressee_id=?) 
               OR (requester_id=? AND addressee_id=?)
        """, (current_user_id, other_user['user_id'], other_user['user_id'], current_user_id)).fetchone()

        if not friendship or friendship['status'] != 'accepted':
            flash("You need to be friends to chat!", "warning")
            return redirect(url_for('notifications_page'))

        # New Message (DM)
        if request.method == 'POST':
            content = request.form.get('content')
            if content:
                conn.execute(
                    "INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)",
                    (current_user_id, other_user['user_id'], content)
                )
                conn.commit()
            return redirect(url_for('chat', username=username))

        # Fetch DM Messages
        messages = conn.execute("""
            SELECT m.message_id, m.content, m.created_at, u.username AS sender_username, m.is_encrypted, COALESCE(p.display_name, u.username) as display_name
            FROM messages m
            JOIN users u ON m.sender_id = u.user_id
            LEFT JOIN user_profiles p ON u.user_id=p.user_id
            WHERE (m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)
            ORDER BY m.created_at ASC
        """, (current_user_id, other_user['user_id'], other_user['user_id'], current_user_id)).fetchall()

    # Common Context
    chats_list = get_user_chats(current_user_id)
    # Get friends for group creation
    friends = get_friends(current_user_id)
    
    groups_query = conn.execute("""
        SELECT g.group_id, g.name, g.description,
               (SELECT content FROM group_messages WHERE group_id = g.group_id ORDER BY created_at DESC LIMIT 1) as last_message
        FROM group_chats g
        JOIN group_members gm ON g.group_id = gm.group_id
        WHERE gm.user_id = ?
        ORDER BY g.created_at DESC
    """, (current_user_id,)).fetchall()

    return render_template(
        'chat_private.html',
        messages=messages,
        recipient=other_user,
        chats=chats_list,
        groups=groups_query,
        friends=friends, # Pass friends list
        current_chat=other_user,
        currentGroup=current_group
    )

#on it rn ask chatgpt to exp this  was  Hard
@socketio.on('connect')
def handle_connect():
    if 'username' not in session:
        return False
    online_users[session['username']] = request.sid

@socketio.on('disconnect')
def handle_disconnect():
    for user, sid in list(online_users.items()):
        if sid == request.sid:
            online_users.pop(user)
            break

#send message 
@socketio.on('send_message')
def handle_message(data):
    sender_username = session.get('username')
    msg = data.get('msg')
    recipient_username = data.get('recipient')
    is_encrypted = data.get('is_encrypted', 0) # Default to 0 (False)
    
    if not sender_username or not msg or not recipient_username:
        return

    conn = get_db()
    sender_id = conn.execute("SELECT user_id FROM users WHERE username = ?", (sender_username,)).fetchone()['user_id']
    recipient_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (recipient_username,)).fetchone()
    if not recipient_row:
        return
    recipient_id = recipient_row['user_id']

    cursor = conn.execute("INSERT INTO messages (sender_id, recipient_id, content, is_encrypted) VALUES (?, ?, ?, ?)",
                 (sender_id, recipient_id, msg, is_encrypted))
    conn.commit()
    message_id = cursor.lastrowid

    # real time text
    recipient_sid = online_users.get(recipient_username)
    payload = {'user': sender_username, 'msg': msg, 'is_encrypted': is_encrypted, 'message_id': message_id}
    if recipient_sid:
        emit('message', payload, room=recipient_sid)
    emit('message', payload, room=request.sid) 

@socketio.on('send_group_message')
def handle_group_message(data):
    sender_username = session.get('username')
    msg = data.get('msg')
    group_id = data.get('group_id')
    is_encrypted = data.get('is_encrypted', 0)
    
    if not sender_username or not msg or not group_id:
        return
    
    conn = get_db()
    sender_id = conn.execute("SELECT user_id FROM users WHERE username = ?", (sender_username,)).fetchone()['user_id']
    
    # Insert message
    cursor = conn.execute(
        "INSERT INTO group_messages (group_id, sender_id, content, is_encrypted) VALUES (?, ?, ?, ?)",
        (group_id, sender_id, msg, is_encrypted)
    )
    conn.commit()
    message_id = cursor.lastrowid
    
    # Broadcast to all group members
    emit('group_message', {
        'user': sender_username,
        'msg': msg,
        'group_id': group_id,
        'is_encrypted': is_encrypted,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'message_id': message_id
    }, room=f'group_{group_id}')

@socketio.on('join_group')
def on_join_group(data):
    group_id = data.get('group_id')
    if 'username' in session:
        from flask_socketio import join_room
        join_room(f'group_{group_id}')

@socketio.on('leave_group')
def on_leave_group(data):
    group_id = data.get('group_id')
    if 'username' in session:
        from flask_socketio import leave_room
        leave_room(f'group_{group_id}')

@app.route('/join_community/<int:community_id>', methods=['POST'])
def join_community(community_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    user_id = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()['user_id']

    # are  You a member check
    exists = conn.execute("""
        SELECT 1 FROM community_members WHERE user_id = ? AND community_id = ?
    """, (user_id, community_id)).fetchone()

    if exists:
        return redirect(url_for('community', community_id=community_id))  # Already a member

    conn.execute("INSERT INTO community_members (user_id, community_id) VALUES (?, ?)", (user_id, community_id))
    conn.commit()
    return redirect(url_for('community', community_id=community_id))

@app.route('/leave_community/<int:community_id>', methods=['POST'])
def leave_community(community_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    
    # Get user ID from session
    user_row = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", 
        (session['username'],)
    ).fetchone()

    if not user_row:
        return redirect(url_for('login'))  # Safety check

    user_id = user_row['user_id']

    # Check if user is actually a member
    exists = conn.execute("""
        SELECT 1 FROM community_members WHERE user_id = ? AND community_id = ?
    """, (user_id, community_id)).fetchone()

    if not exists:
        return redirect(url_for('community', community_id=community_id))  # Not a member

    # Delete membership
    conn.execute(
        "DELETE FROM community_members WHERE user_id = ? AND community_id = ?",
        (user_id, community_id)
    )
    conn.commit()

    return redirect(url_for('community', community_id=community_id))

#  Not even implemented We hope it works 
@app.route('/friend/request/<username>', methods=['POST'])
def send_friend_request(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    requester_id = conn.execute(
        "SELECT user_id FROM users WHERE username=?",
        (session['username'],)
    ).fetchone()['user_id']

    target = conn.execute(
        "SELECT user_id FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not target:
        return "User not found"

    try:
        conn.execute("""
            INSERT INTO friends (requester_id, addressee_id, status)
            VALUES (?, ?, 'pending')
        """, (requester_id, target['user_id']))
        conn.commit()
        
        # Notify the recipient
        create_notification(
            user_id=target['user_id'],
            actor_id=requester_id,
            notif_type='friend_request',
            message=f"{session['username']} sent you a friend request",
            link=url_for('notifications_page'), # Redirect to notifications page to accept/decline
            reference_id=requester_id # using reference_id as the requester_id can be useful
        )
        
    except sqlite3.IntegrityError:
        pass  # already exists

    return redirect(url_for('userprofile', username=username))

@app.route('/friend/accept/<int:friendship_id>', methods=['POST'])
def accept_friend(friendship_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    user_id = conn.execute(
        "SELECT user_id FROM users WHERE username=?",
        (session['username'],)
    ).fetchone()['user_id']

    conn.execute("""
        UPDATE friends
        SET status='accepted', responded_at=CURRENT_TIMESTAMP
        WHERE friendship_id=? AND addressee_id=?
    """, (friendship_id, user_id))

    # Get the requester ID to notify them
    friend_req = conn.execute("SELECT requester_id FROM friends WHERE friendship_id=?", (friendship_id,)).fetchone()
    if friend_req:
        create_notification(
            user_id=friend_req['requester_id'],
            actor_id=user_id,
            notif_type='friend_accept',
            message=f"{session['username']} accepted your friend request",
            link=url_for('userprofile', username=session['username'])
        )

    conn.commit()
    return redirect(url_for('notifications_page'))

@app.route('/friend/decline/<int:friendship_id>', methods=['POST'])
def decline_friend(friendship_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    user_id = conn.execute("SELECT user_id FROM users WHERE username=?", (session['username'],)).fetchone()['user_id']

    # Delete the request
    conn.execute("""
        DELETE FROM friends
        WHERE friendship_id=? AND addressee_id=? AND status='pending'
    """, (friendship_id, user_id))
    
    conn.commit()
    return redirect(url_for('notifications_page'))

@app.route('/api/keys/publish', methods=['POST'])
def publish_key():
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    data = request.get_json()
    public_key = data.get('public_key')
    
    if not public_key:
        return {'error': 'No key provided'}, 400
        
    conn = get_db()
    conn.execute("UPDATE users SET public_key = ? WHERE username = ?", (public_key, session['username']))
    conn.commit()
    
    return {'status': 'success'}

@app.route('/api/keys/<int:user_id>', methods=['GET'])
def get_user_key(user_id):
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
        
    conn = get_db()
    row = conn.execute("SELECT public_key FROM users WHERE user_id = ?", (user_id,)).fetchone()
    
    if not row:
        return {'error': 'User not found'}, 404
        
    return {'public_key': row['public_key']}

@app.route('/my_messages', methods=['GET', 'POST'])
def my_messages():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']

    # send a text
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id')
        content = request.form.get('content')
        if recipient_id and content:
            conn.execute(
                "INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)",
                (current_user_id, recipient_id, content)
            )
            conn.commit()
        return redirect(url_for('my_messages'))

    # who have u texted so far + your contacts
    # list of dictionary
    chats = get_user_chats(current_user_id)

    # --- UPDATED: FETCH GROUP CHATS HERE TOO ---
    groups_query = conn.execute("""
        SELECT g.group_id, g.name, g.description,
               (SELECT content FROM group_messages WHERE group_id = g.group_id ORDER BY created_at DESC LIMIT 1) as last_message
        FROM group_chats g
        JOIN group_members gm ON g.group_id = gm.group_id
        WHERE gm.user_id = ?
        ORDER BY g.created_at DESC
    """, (current_user_id,)).fetchall()

    # current chat
    if chats:
        current_chat = chats[0] 
        messages = conn.execute("""
            SELECT m.content, m.created_at, u.username AS sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.user_id
            WHERE (m.sender_id = ? AND m.recipient_id = ?)
               OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.created_at ASC
        """, (current_user_id, current_chat['user_id'], current_chat['user_id'], current_user_id)).fetchall()
    else:
        current_chat = None
        messages = []

    # Get friends for group creation
    friends = get_friends(current_user_id)

    return render_template(
        'chat_private.html',
        messages=messages,
        chats=chats,
        groups=groups_query,
        friends=friends, # Pass friends list
        current_chat=current_chat,
        recipient=current_chat 
    )

@app.route('/api/all-users', methods=['GET'])
def get_all_users():
    """API endpoint to search users for adding contacts"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    query = request.args.get('q', '').strip()
    
    try:
        conn = get_db()
        current_user_id = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (session['username'],)
        ).fetchone()['user_id']
        
        # Base SQL: Find users who are NOT you
        sql = """
            SELECT u.username, 
                   COALESCE(p.display_name, u.username) as display_name
            FROM users u
            LEFT JOIN user_profiles p ON u.user_id = p.user_id
            WHERE u.user_id != ? 
        """
        params = [current_user_id]

        # If searching, filter the results
        if query:
            sql += " AND (u.username LIKE ? OR p.display_name LIKE ?)"
            search_term = f"%{query}%"
            params.extend([search_term, search_term])
        
        sql += " ORDER BY p.display_name LIMIT 20"
        
        users_rows = conn.execute(sql, params).fetchall()
        
        # Convert to list
        users = [{'username': user['username'], 'display_name': user['display_name']} for user in users_rows]
        
        return {'users': users}

    except Exception as e:
        print(f"Error in get_all_users: {e}")
        return {'error': str(e), 'users': []}, 500
  
@app.route('/api/chats', methods=['GET'])
def get_chats_api():
    """API endpoint to get updated chats list"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    chats = get_user_chats(current_user_id)
    return {'chats': chats}

@app.route('/api/chat-messages/<username>', methods=['GET'])
def get_chat_messages(username):
    """API endpoint to get messages with a specific user"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    other_user = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (username,)
    ).fetchone()
    
    if not other_user:
        return {'error': 'User not found'}, 404
    
    other_user_id = other_user['user_id']
    
    messages = conn.execute("""
        SELECT m.content, m.created_at, u.username AS sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
    """, (current_user_id, other_user_id, other_user_id, current_user_id)).fetchall()
    
    return {
        'messages': [{'content': m['content'], 'sender_username': m['sender_username'], 'created_at': m['created_at']} for m in messages]
    }

@app.route('/api/send-image', methods=['POST'])
def send_image():
    """API endpoint to send an image message"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    # Check if image file is in request
    if 'image' not in request.files:
        return {'error': 'No image file provided'}, 400
    
    file = request.files['image']
    
    if file.filename == '':
        return {'error': 'No file selected'}, 400
    
    if not allowed_file(file.filename):
        return {'error': 'Invalid file type. Only images allowed'}, 400
    
    try:
        conn = get_db()
        current_user_id = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (session['username'],)
        ).fetchone()['user_id']
        
        # Get recipient or group_id from request
        recipient = request.form.get('recipient')
        group_id = request.form.get('group_id')
        
        if not recipient and not group_id:
            return {'error': 'Recipient or group_id required'}, 400
        
        # Save the image file
        filename = secure_filename(f"{current_user_id}_{datetime.now().timestamp()}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Store image path in message
        image_url = f"/static/uploads/{filename}"
        message_content = f'[IMAGE]{image_url}'
        
        if group_id:
            # Send to group
            group_id = int(group_id)
            
            # Check if user is member of group
            is_member = conn.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
                (group_id, current_user_id)
            ).fetchone()
            
            if not is_member:
                os.remove(filepath)  # Clean up file
                return {'error': 'Not a member of this group'}, 403
            
            # Store message in database
            conn.execute(
                "INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)",
                (group_id, current_user_id, message_content)
            )
            conn.commit()
        else:
            # Send to individual
            other_user = conn.execute(
                "SELECT user_id FROM users WHERE username = ?", (recipient,)
            ).fetchone()
            
            if not other_user:
                os.remove(filepath)  # Clean up file
                return {'error': 'User not found'}, 404
            
            other_user_id = other_user['user_id']
            
            # Store message in database
            conn.execute(
                "INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)",
                (current_user_id, other_user_id, message_content)
            )
            conn.commit()
        
        return {'success': True, 'message': 'Image sent successfully', 'image_url': image_url}, 200
    
    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/api/create-group', methods=['POST'])
def create_group_api():
    """Create a new group chat"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    data = request.get_json()
    group_name = data.get('group_name', '').strip()
    description = data.get('description', '').strip()
    member_usernames = data.get('member_ids', []) # Frontend actually sends usernames
    
    if not group_name:
        return {'error': 'Group name is required'}, 400
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    try:
        # Create group
        conn.execute(
            "INSERT INTO group_chats (name, description, creator_id) VALUES (?, ?, ?)",
            (group_name, description, current_user_id)
        )
        conn.commit()
        
        # Get the group ID
        group = conn.execute(
            "SELECT group_id FROM group_chats WHERE name = ? AND creator_id = ? ORDER BY created_at DESC LIMIT 1",
            (group_name, current_user_id)
        ).fetchone()
        group_id = group['group_id']
        
        # Add creator as member
        conn.execute(
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
            (group_id, current_user_id)
        )
        
        # Add other members (Look up ID by username)
        for username in member_usernames:
            user = conn.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()
            if user:
                try:
                    conn.execute(
                        "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
                        (group_id, user['user_id'])
                    )
                except:
                    pass
        
        conn.commit()
        return {'success': True, 'group_id': group_id, 'message': f'Group "{group_name}" created!'}
    except Exception as e:
        print(f"Group creation error: {e}")
        return {'error': str(e)}, 400

@app.route('/api/group/<int:group_id>/messages', methods=['GET'])
def get_group_messages(group_id):
    """Get messages from a group chat"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    # Check if user is member of group
    is_member = conn.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, current_user_id)
    ).fetchone()
    
    if not is_member:
        return {'error': 'Not a member of this group'}, 403
    
    messages = conn.execute("""
        SELECT gm.message_id, gm.content, gm.created_at, u.username AS sender_username, p.display_name
        FROM group_messages gm
        JOIN users u ON gm.sender_id = u.user_id
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE gm.group_id = ?
        ORDER BY gm.created_at ASC
    """, (group_id,)).fetchall()
    
    group = conn.execute(
        "SELECT * FROM group_chats WHERE group_id = ?", (group_id,)
    ).fetchone()
    
    members = conn.execute("""
        SELECT u.user_id, u.username, p.display_name
        FROM group_members gm
        JOIN users u ON gm.user_id = u.user_id
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE gm.group_id = ?
    """, (group_id,)).fetchall()
    
    return {
        'group': {'group_id': group['group_id'], 'name': group['name'], 'description': group['description']},
        'messages': [{'message_id': m['message_id'], 'content': m['content'], 'sender_username': m['sender_username'], 'display_name': m['display_name'], 'created_at': m['created_at']} for m in messages],
        'members': [{'user_id': m['user_id'], 'username': m['username'], 'display_name': m['display_name']} for m in members]
    }

@app.route('/api/groups', methods=['GET'])
def get_user_groups():
    """Get all groups for current user"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    groups = conn.execute("""
        SELECT g.group_id, g.name, g.description, g.created_at,
               (SELECT COUNT(*) FROM group_members WHERE group_id = g.group_id) AS member_count,
               (SELECT content FROM group_messages WHERE group_id = g.group_id ORDER BY created_at DESC LIMIT 1) AS last_message
        FROM group_chats g
        JOIN group_members gm ON g.group_id = gm.group_id
        WHERE gm.user_id = ?
        ORDER BY g.created_at DESC
    """, (current_user_id,)).fetchall()
    
    return {
        'groups': [{'group_id': g['group_id'], 'name': g['name'], 'description': g['description'], 'member_count': g['member_count'], 'last_message': g['last_message'] or ''} for g in groups]
    }

@app.route('/api/add-contact', methods=['POST'])
def api_add_contact():
    """API endpoint to add a new contact"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    data = request.get_json()
    contact_username = data.get('contact_username')
    contact_name = data.get('contact_name') or contact_username
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    contact_user = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (contact_username,)
    ).fetchone()
    
    if not contact_user:
        return {'error': 'User not found'}, 404
    
    contact_user_id = contact_user['user_id']
    
    if contact_user_id == current_user_id:
        return {'error': 'Cannot add yourself as a contact'}, 400
    
    # Check if contact already exists
    existing = conn.execute(
        "SELECT 1 FROM contacts WHERE user_id = ? AND contact_user_id = ?",
        (current_user_id, contact_user_id)
    ).fetchone()
    
    if existing:
        return {'error': 'This contact already exists'}, 400
    
    try:
        conn.execute(
            "INSERT INTO contacts (user_id, contact_user_id, contact_name) VALUES (?, ?, ?)",
            (current_user_id, contact_user_id, contact_name)
        )
        conn.commit()
        return {'success': True, 'message': f'Added {contact_username} to contacts'}
    except Exception as e:
        return {'error': str(e)}, 400

@app.route('/api/message/<int:message_id>/delete', methods=['POST'])
def delete_message(message_id):
    """Delete a message"""
    if 'username' not in session:
        return {'error': 'Not logged in'}, 401
    
    conn = get_db()
    current_user_id = conn.execute(
        "SELECT user_id FROM users WHERE username = ?", (session['username'],)
    ).fetchone()['user_id']
    
    # Check DM messages
    msg = conn.execute("SELECT * FROM messages WHERE message_id = ?", (message_id,)).fetchone()
    group_msg = None
    
    if not msg:
        # Check Group messages
        group_msg = conn.execute("SELECT * FROM group_messages WHERE message_id = ?", (message_id,)).fetchone()
        if not group_msg:
            return {'error': 'Message not found'}, 404
        
        if group_msg['sender_id'] != current_user_id:
             return {'error': 'Unauthorized'}, 403
             
        # Delete group message
        conn.execute("DELETE FROM group_messages WHERE message_id = ?", (message_id,))
        conn.commit()
        
        # Broadcast deletion
        socketio.emit('message_deleted', {'message_id': message_id, 'group_id': group_msg['group_id']}, room=f"group_{group_msg['group_id']}")
        
    else:
        if msg['sender_id'] != current_user_id:
            return {'error': 'Unauthorized'}, 403
            
        # Delete DM
        conn.execute("DELETE FROM messages WHERE message_id = ?", (message_id,))
        conn.commit()
        
        # Notify recipient (find their SID)
        recipient = conn.execute("SELECT username FROM users WHERE user_id = ?", (msg['recipient_id'],)).fetchone()
        if recipient:
            recipient_username = recipient['username']
            recipient_sid = online_users.get(recipient_username)
            if recipient_sid:
                 socketio.emit('message_deleted', {'message_id': message_id}, room=recipient_sid)
        
        # Notify sender (current user) too, via socket for consistency if they have multiple tabs
        sender_sid = online_users.get(session['username'])
        if sender_sid:
            socketio.emit('message_deleted', {'message_id': message_id}, room=sender_sid)

    return {'success': True}

# Explore page - show all communities except the ones user is already in

@app.route('/explore')
def explore():
    conn = get_db()

    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    communities = conn.execute("""
        SELECT *
        FROM communities
        WHERE community_id NOT IN (
            SELECT community_id
            FROM community_members
            WHERE user_id = ?
        )
        ORDER BY name ASC
    """, (user_id,)).fetchall()

    return render_template(
        'explore.html',
        communities=communities
    )

# ==========================================
# === FIND A FRIEND & GAMES (Phoebe) ===
# ==========================================

# --- 1. GAME DATA ---
# 9 Tasks implies a 3x3 Grid
BINGO_TASKS = [
    {"id": 1, "task": "Drank Milo"}, {"id": 2, "task": "5 min walk"},
    {"id": 3, "task": "Ate Hawker Meal"}, {"id": 4, "task": "Called a friend"},
    {"id": 5, "task": "Read News"}, {"id": 6, "task": "Watered Plants"},
    {"id": 7, "task": "Used Dialect"}, {"id": 8, "task": "Listened to Radio"},
    {"id": 9, "task": "Slept by 10pm"}
]

# UPDATED: Real iTunes Preview URLs added to MUSIC_ROUNDS
MUSIC_ROUNDS = [
    {
        "song": "Deja Vu",
        "artist": "Tomorrow X Together",
        "year": "2023",
        "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview112/v4/d0/8e/88/d08e8891-e5c4-7d42-8a3f-c3d3f3e3f3e3/mzaf_1234567890.plus.aac.p.m4a",
        "answer": "Deja Vu",
        "options": ["Beautiful Strangers", "Deja Vu", "Chasing That Feeling", "Love Language"]
    },
    {
        "song": "It Must Have Been Love",
        "artist": "Roxette",
        "year": "1990",
        "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview115/v4/09/44/28/09442801-7892-0b61-2f7a-853158e945d8/mzaf_3800262142279140990.plus.aac.p.m4a",
        "answer": "It Must Have Been Love",
        "options": ["Listen to Your Heart", "It Must Have Been Love", "The Look", "Joyride"]
    },
    {
        "song": "Chk Chk Boom",
        "artist": "Stray Kids",
        "year": "2024",
        "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview211/v4/21/53/7d/21537d80-50d4-0770-466c-48762512140a/mzaf_13778523362678187802.plus.aac.p.m4a",
        "answer": "Chk Chk Boom",
        "options": ["Chk Chk Boom", "Megaverse", "Do It", "LALALALA"]
    },
    {
        "song": "Dancing Queen",
        "artist": "ABBA",
        "year": "1976",
        "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview115/v4/64/73/42/64734204-c54d-6d55-1563-305404990924/mzaf_4682062773229871578.plus.aac.p.m4a",
        "answer": "Dancing Queen",
        "options": ["Mamma Mia", "Dancing Queen", "Super Trouper", "Waterloo"]
    },
    {
        "song": "Easier",
        "artist": "5 Seconds of Summer",
        "year": "2019",
        "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview125/v4/d5/07/77/d507779e-4770-369f-4315-7729bc181b52/mzaf_10036625805561571542.plus.aac.p.m4a",
        "answer": "Easier",
        "options": ["Easier", "A Different Way", "Entertainer", "Youngblood"]
    }
]

# --- TXT MINI-CROSSWORD (Corrected Intersections) ---
# Grid Size needed: 10x10

CROSSWORD_LAYOUT = {
    # Format: (row, col): letter
    # TAEHYUN - across from (0,2) to (0,8)
    (0, 2): ('T', 'across', 'TAEHYUN', 'Logical member'),
    (0, 3): ('A', 'across', 'TAEHYUN', 'Logical member'),
    (0, 4): ('E', 'across', 'TAEHYUN', 'Logical member'),
    (0, 5): ('H', 'across', 'TAEHYUN', 'Logical member'),
    (0, 6): ('Y', 'across', 'TAEHYUN', 'Logical member'),
    (0, 7): ('U', 'across', 'TAEHYUN', 'Logical member'),
    (0, 8): ('N', 'across', 'TAEHYUN', 'Logical member'),
    
    # TXT - down from (1,2) to (2,2)
    (1, 2): ('X', 'down', 'TXT', 'Kpop group debuted 2019'),
    (2, 2): ('T', 'down', 'TXT', 'Kpop group debuted 2019'),
    
    # FROST - across from (2,4) to (2,8)
    (2, 4): ('F', 'across', 'FROST', 'Song in Chaos Chapter'),
    (2, 5): ('R', 'across', 'FROST', 'Song in Chaos Chapter'),
    (2, 6): ('O', 'across', 'FROST', 'Song in Chaos Chapter'),
    (2, 7): ('S', 'across', 'FROST', 'Song in Chaos Chapter'),
    (2, 8): ('T', 'across', 'FROST', 'Song in Chaos Chapter'),
    
    # YEONJUN - down from (0,6) to (6,6)
    (1, 6): ('E', 'down', 'YEONJUN', 'Legendary trainee'),
    (2, 6): ('O', 'down', 'YEONJUN', 'Legendary trainee'),  # Intersects FROST
    (3, 6): ('N', 'down', 'YEONJUN', 'Legendary trainee'),
    (4, 6): ('J', 'down', 'YEONJUN', 'Legendary trainee'),
    (5, 6): ('U', 'down', 'YEONJUN', 'Legendary trainee'),
    (6, 6): ('N', 'down', 'YEONJUN', 'Legendary trainee'),
    
    # BEOMGYU - across from (5,0) to (5,6)
    (5, 0): ('B', 'across', 'BEOMGYU', 'Mood maker'),
    (5, 1): ('E', 'across', 'BEOMGYU', 'Mood maker'),
    (5, 2): ('O', 'across', 'BEOMGYU', 'Mood maker'),
    (5, 3): ('M', 'across', 'BEOMGYU', 'Mood maker'),
    (5, 4): ('G', 'across', 'BEOMGYU', 'Mood maker'),
    (5, 5): ('Y', 'across', 'BEOMGYU', 'Mood maker'),
    (5, 6): ('U', 'across', 'BEOMGYU', 'Mood maker'),  # Intersects YEONJUN
    
    # MOA - down from (4,2) to (6,2)
    (4, 2): ('M', 'down', 'MOA', 'Fandom name'),
    (6, 2): ('A', 'down', 'MOA', 'Fandom name'),
}

# Helper to get all cells for the grid
def get_all_crossword_cells():
    """Returns set of all valid cells (r,c) in the crossword"""
    return set(CROSSWORD_LAYOUT.keys())

# Helper to get word groups for validation
def get_crossword_words():
    """Returns dictionary of word_id -> {cells, word, direction, clue}"""
    words = {}
    for cell, (letter, direction, word, clue) in CROSSWORD_LAYOUT.items():
        word_id = f"{word}_{direction}"
        if word_id not in words:
            words[word_id] = {
                'cells': [],
                'word': word,
                'direction': direction,
                'clue': clue
            }
        words[word_id]['cells'].append(cell)
    return words


# Ensure Game Messages Table Exists (Run once)
def init_game_tables():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS game_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

# --- 2. HELPER FUNCTIONS ---

def get_utc_today():
    return datetime.now(timezone.utc).date().isoformat()

def update_streak(user_id, game):
    conn = get_db()
    db_game_name = 'song' if game == 'guess_song' else game
    
    stats = conn.execute("SELECT * FROM user_stats WHERE user_id=?", (user_id,)).fetchone()
    today = get_utc_today()
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    
    col_streak, col_date = f"streak_{db_game_name}", f"last_{db_game_name}_date"
    
    # Handle case where user_stats row doesn't exist yet
    if not stats:
        conn.execute(f"INSERT INTO user_stats (user_id, {col_streak}, {col_date}) VALUES (?, ?, ?)", 
                     (user_id, 1, today))
        conn.commit()
        return

    current = stats[col_streak]
    last = stats[col_date]
    
    if last == today: return
    
    new_streak = current + 1 if last == yesterday else 1
    
    conn.execute(f"UPDATE user_stats SET {col_streak}=?, {col_date}=? WHERE user_id=?", (new_streak, today, user_id))
    conn.commit()

# --- HELPER: Checks if a game is completed ---
def get_game_status(user_id, game_type):
    if game_type == 'live_chat': return "available"

    conn = get_db()
    today = datetime.now(timezone.utc).date().isoformat()
    
    # [FIX] Map 'guess_song' to 'song' so we check the right DB column
    db_game_name = 'song' if game_type == 'guess_song' else game_type
    
    # Check if we played today
    stats = conn.execute(f"SELECT last_{db_game_name}_date FROM user_stats WHERE user_id=?", (user_id,)).fetchone()
    
    if stats and stats[f'last_{db_game_name}_date'] == today:
        return "completed"

    # Check if a session is currently active (waiting for partner)
    if game_type != 'bingo':
        active = conn.execute("""
            SELECT 1 FROM game_sessions 
            WHERE game_type=? AND (player_1_id=? OR player_2_id=?) AND status='active'
        """, (game_type, user_id, user_id)).fetchone()
        if active: 
            return "in_progress"
            
    return "available"


def find_match_priority(conn, user_id, game_type):
    user = conn.execute("SELECT age FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not user: return None
    my_age = user['age']

    is_youth = my_age < 30
    is_elderly = my_age > 50
    
    target_condition = ""
    if is_youth: target_condition = "AND u.age > 50"
    elif is_elderly: target_condition = "AND u.age < 30"
    
    if target_condition:
        query = f"""
            SELECT s.session_id, s.player_1_id 
            FROM game_sessions s
            JOIN users u ON s.player_1_id = u.user_id
            WHERE s.game_type=? AND s.player_2_id IS NULL AND s.status='active' 
            AND s.player_1_id != ? {target_condition}
            ORDER BY s.created_at ASC LIMIT 1
        """
        match = conn.execute(query, (game_type, user_id)).fetchone()
        if match: return match

    return conn.execute("""
        SELECT session_id, s.player_1_id 
        FROM game_sessions s
        WHERE s.game_type=? AND s.player_2_id IS NULL AND s.status='active' 
        AND s.player_1_id != ?
        ORDER BY s.created_at ASC LIMIT 1
    """, (game_type, user_id)).fetchone()
    
# --- 3. GAME ROUTES ---

@app.route('/find-a-friend')
def find_a_friend_hub():
    if 'username' not in session: return redirect(url_for('login'))
    init_game_tables() # Ensure tables exist
    conn = get_db()
    uid = session['user_id']
    
    stats = conn.execute("SELECT * FROM user_stats WHERE user_id=?", (uid,)).fetchone()
    if not stats: stats = {'streak_bingo': 0, 'streak_crossword': 0, 'streak_song': 0}

    status = {
        'bingo': get_game_status(uid, 'bingo'),
        'crossword': get_game_status(uid, 'crossword'),
        'song': get_game_status(uid, 'song') # song uses 'guess_song' in DB calls, handled in helper
    }
    # Pass 'guess_song' key for frontend logic if needed, but helper uses mapped names
    # Fix: Ensure key matches what template expects
    return render_template('find_a_friend.html', stats=stats, status=status)

# --- ROUTE: Game Start Page ---
@app.route('/game/start/<game_type>')
def game_start_page(game_type):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    stats = conn.execute("SELECT * FROM user_stats WHERE user_id=?", (uid,)).fetchone()
    if not stats: 
        stats = {'streak_bingo':0, 'streak_crossword':0, 'streak_song':0}
    
    status = get_game_status(uid, game_type)
    
    # [FIX] BINGO EXCEPTION: Always allow Bingo, even if 'completed'
    if game_type == 'bingo':
        status = 'available'

    # Fetch Friend Activity (Only needed for Bingo)
    activity = []
    if game_type == 'bingo':
        try:
            raw_activity = conn.execute("""
                SELECT u.username, b.note, b.created_at, b.task_id 
                FROM bingo_progress b JOIN users u ON b.user_id = u.user_id 
                WHERE b.user_id != ? ORDER BY b.created_at DESC LIMIT 5
            """, (uid,)).fetchall()
        except:
            raw_activity = []
        
        for row in raw_activity:
            task_name = next((t['task'] for t in BINGO_TASKS if t['id'] == row['task_id']), "Task")
            note_content = f"Completed: {task_name}"
            if row['note']: note_content += f" — \"{row['note']}\""
            activity.append({'username': row['username'], 'note': note_content})

    return render_template('game_start.html', game=game_type, stats=stats, status=status, activity=activity)

@app.route('/lobby/<game>')
def game_lobby(game):
    """Direct matchmaking - no waiting page"""
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    
    conn = get_db()
    uid = session['user_id']
    
    # [FIX] Clean ghost sessions but KEEP Crossword sessions active for longer (24h)
    # This prevents Crossword progress from being deleted if they leave the page
    if game == 'crossword':
        conn.execute("""
            DELETE FROM game_sessions 
            WHERE game_type = ? 
            AND player_1_id = ? 
            AND player_2_id IS NULL 
            AND created_at < datetime('now', '-24 hours')
        """, (game, uid))
    else:
        conn.execute("""
            DELETE FROM game_sessions 
            WHERE game_type = ? 
            AND player_1_id = ? 
            AND player_2_id IS NULL 
            AND created_at < datetime('now', '-10 minutes')
        """, (game, uid))
    conn.commit()
    
    # Check if already in active game
    existing = conn.execute("""
        SELECT session_id, player_2_id FROM game_sessions 
        WHERE game_type=? 
        AND (player_1_id=? OR player_2_id=?) 
        AND status='active'
    """, (game, uid, uid)).fetchone()
    
    if existing and existing['player_2_id']:
        return redirect(url_for(f'game_{game}_play'))
    
    # Try to find a match
    match = find_match_priority(conn, uid, game)
    
    if match:
        # Match found! Update session and redirect
        sid = match['session_id']
        conn.execute("UPDATE game_sessions SET player_2_id=? WHERE session_id=?", (uid, sid))
        conn.commit()
        
        # [FIX] Notify Player 1 that a match is found
        socketio.emit('match_found', {'game_type': game, 'session_id': sid}, room=str(sid))
        
        return redirect(url_for(f'game_{game}_play'))
    
    # No match found - create waiting session
    if not existing:
        conn.execute("INSERT INTO game_sessions (game_type, player_1_id, status) VALUES (?, ?, 'active')", (game, uid))
        conn.commit()
        sid = conn.execute("SELECT last_insert_rowid() as id").fetchone()['id']
    else:
        sid = existing['session_id']
    
    return render_template('lobby.html', game=game, session_id=sid)


@app.route('/play/crossword')
def game_crossword_play():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # 1. Get active game
    game_session = conn.execute("""
        SELECT * FROM game_sessions 
        WHERE (player_1_id = ? OR player_2_id = ?) 
        AND game_type = 'crossword' 
        AND status IN ('active', 'completed')
        ORDER BY created_at DESC LIMIT 1
    """, (uid, uid)).fetchone()
    
    if not game_session: return redirect(url_for('game_lobby', game='crossword'))
    if not game_session['player_2_id']: return redirect(url_for('game_lobby', game='crossword'))
    
    session_id = game_session['session_id']
    my_role = 'p1' if game_session['player_1_id'] == uid else 'p2'
    
    partner_id = game_session['player_2_id'] if my_role == 'p1' else game_session['player_1_id']
    partner = conn.execute("SELECT username FROM users WHERE user_id = ?", (partner_id,)).fetchone()
    
    # [FIX 1] Hardcoded Intersections
    intersections = {(2, 6), (5, 6), (5, 2)} 

    editable_cells = []
    for cell, (letter, direction, word, clue) in CROSSWORD_LAYOUT.items():
        if (my_role == 'p1' and direction == 'across'):
            editable_cells.append(cell)
        elif (my_role == 'p2' and direction == 'down'):
            editable_cells.append(cell)
        elif cell in intersections:
            editable_cells.append(cell)

    # Get State
    state_row = conn.execute("SELECT grid_state, words_found FROM crossword_states WHERE session_id = ?", (session_id,)).fetchone()
    current_state = json.loads(state_row['grid_state']) if state_row and state_row['grid_state'] else {}
    words_found = json.loads(state_row['words_found']) if state_row and state_row['words_found'] else []

    # Chat History
    chat_history = conn.execute("""
        SELECT u.username, m.content FROM game_messages m
        JOIN users u ON m.user_id = u.user_id WHERE m.session_id = ? ORDER BY m.created_at ASC
    """, (session_id,)).fetchall()

    # Layout Data for JS
    layout_data = {}
    for (r, c), (l, d, w, clue) in CROSSWORD_LAYOUT.items():
        layout_data[f"{r},{c}"] = {'letter': l, 'direction': d, 'word': w}
    
    # [FIX 2] Generate "all_words" CORRECTLY (All words, not just mine)
    all_words_set = set()
    for (r, c), (l, d, w, clue) in CROSSWORD_LAYOUT.items():
        word_id = f"{w}_{d}" # Unique ID: e.g., "FROST_across"
        all_words_set.add(word_id)
    all_words = list(all_words_set)
    
    # Generate My Clues
    my_clues = []
    seen_clue_words = set()
    for (r,c), (l, d, w, clue) in CROSSWORD_LAYOUT.items():
        if w not in seen_clue_words:
            if (my_role == 'p1' and d == 'across') or (my_role == 'p2' and d == 'down'):
                my_clues.append({'word': w, 'clue': clue})
                seen_clue_words.add(w)

    return render_template('crossword.html',
                        session_id=session_id,
                        partner_name=partner['username'] if partner else "Partner",
                        my_role=my_role,
                        layout=set(CROSSWORD_LAYOUT.keys()),
                        layout_data=layout_data,
                        current_state=current_state,
                        words_found=words_found,
                        all_words=all_words, # Now contains ALL words
                        chat_history=chat_history,
                        my_clues=my_clues,
                        editable_cells=editable_cells)
        
# SOCKET HANDLER

@socketio.on('check_for_match')
def check_for_match(data):
    """Poll for match updates"""
    session_id = data.get('session_id')
    
    conn = get_db()
    game_session = conn.execute("""
        SELECT player_2_id, game_type FROM game_sessions 
        WHERE session_id = ?
    """, (session_id,)).fetchone()
    
    if game_session and game_session['player_2_id']:
        emit('match_found', {
            'game_type': game_session['game_type']
        })

@socketio.on('crossword_move')
def handle_crossword_move(data):
    session_id = data.get('session_id')
    row = data.get('row')
    col = data.get('col')
    letter = data.get('letter', '')
    
    conn = get_db()
    
    # Save to DB
    state_row = conn.execute("SELECT grid_state FROM crossword_states WHERE session_id = ?", (session_id,)).fetchone()
    grid_state = json.loads(state_row['grid_state']) if state_row else {}
    
    cell_key = f"{row}_{col}"
    if letter: grid_state[cell_key] = letter
    else: grid_state.pop(cell_key, None)
    
    if state_row:
        conn.execute("UPDATE crossword_states SET grid_state = ? WHERE session_id = ?", (json.dumps(grid_state), session_id))
    else:
        conn.execute("INSERT INTO crossword_states (session_id, grid_state) VALUES (?, ?)", (session_id, json.dumps(grid_state)))
    conn.commit()
    
    # [FIX] Broadcast to room=str(session_id) so the partner sees it
    emit('update_grid', {
        'row': row,
        'col': col,
        'letter': letter
    }, room=str(session_id), skip_sid=request.sid)

@socketio.on('send_crossword_reminder')
def send_crossword_reminder(data):
    """Send reminder notification"""
    if 'user_id' not in session:
        return
    
    session_id = data['session_id']
    conn = get_db()
    
    game_session = conn.execute("""
        SELECT player_1_id, player_2_id FROM game_sessions WHERE session_id = ?
    """, (session_id,)).fetchone()
    
    if not game_session:
        return
    
    partner_id = game_session['player_2_id'] if game_session['player_1_id'] == session['user_id'] else game_session['player_1_id']
    
    create_notification(
        user_id=partner_id,
        actor_id=session['user_id'],
        notif_type='game_reminder',
        message=f"{session['username']} is waiting for you in Crossword!",
        link=url_for('game_crossword_play'),
        reference_id=session_id
    )
    
    emit('reminder_sent', {'success': True}, room=request.sid)

# ==========================================
# GUESS THE SONG - ITUNES API + SYNC
# ==========================================

def fetch_songs_from_itunes():
    """
    Fetch real songs from iTunes API with robust error handling.
    If API fails or no preview is found, uses a fallback.
    """
    songs = []
    
    # 1. Define Queries (The songs you want to find)
    queries = [
        "Deja Vu Tomorrow X Together",
        "It Must Have Been Love Roxette", 
        "Chk Chk Boom Stray Kids",
        "Dancing Queen ABBA",
        "Easier 5 Seconds of Summer"
    ]
    
    # 2. Define Fallbacks (Used if API fails)
    # These have hardcoded previews that we know work or are placeholders
    FALLBACK_SONGS = [
        {
            "song": "Deja Vu", "artist": "Tomorrow X Together", 
            "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview112/v4/d0/8e/88/d08e8891-e5c4-7d42-8a3f-c3d3f3e3f3e3/mzaf_1234567890.plus.aac.p.m4a",
            "answer": "Deja Vu", "options": ["Beautiful Strangers", "Deja Vu", "Chasing That Feeling", "Love Language"]
        },
        {
            "song": "It Must Have Been Love", "artist": "Roxette", 
            "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview115/v4/09/44/28/09442801-7892-0b61-2f7a-853158e945d8/mzaf_3800262142279140990.plus.aac.p.m4a",
            "answer": "It Must Have Been Love", "options": ["Listen to Your Heart", "It Must Have Been Love", "The Look", "Joyride"]
        },
        {
            "song": "Chk Chk Boom", "artist": "Stray Kids", 
            "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview211/v4/21/53/7d/21537d80-50d4-0770-466c-48762512140a/mzaf_13778523362678187802.plus.aac.p.m4a",
            "answer": "Chk Chk Boom", "options": ["Chk Chk Boom", "Megaverse", "Do It", "LALALALA"]
        },
        {
            "song": "Dancing Queen", "artist": "ABBA", 
            "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview115/v4/64/73/42/64734204-c54d-6d55-1563-305404990924/mzaf_4682062773229871578.plus.aac.p.m4a",
            "answer": "Dancing Queen", "options": ["Mamma Mia", "Dancing Queen", "Super Trouper", "Waterloo"]
        },
        {
            "song": "Easier", "artist": "5 Seconds of Summer", 
            "preview": "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview125/v4/d5/07/77/d507779e-4770-369f-4315-7729bc181b52/mzaf_10036625805561571542.plus.aac.p.m4a",
            "answer": "Easier", "options": ["Easier", "A Different Way", "Entertainer", "Youngblood"]
        }
    ]

    import random
    
    for i, query_term in enumerate(queries):
        try:
            # Call iTunes API
            response = requests.get(
                f"https://itunes.apple.com/search?term={quote(query_term)}&limit=1&entity=song",
                timeout=5 # Increased timeout slightly
            )
            
            success = False
            if response.status_code == 200:
                data = response.json()
                if data['resultCount'] > 0:
                    track = data['results'][0]
                    
                    # IMPORTANT: Check if previewUrl actually exists!
                    if track.get('previewUrl'):
                        # Generate "Wrong" options using other songs by same artist
                        wrong_answers = []
                        try:
                            artist_query = requests.get(
                                f"https://itunes.apple.com/search?term={quote(track['artistName'])}&limit=5&entity=song",
                                timeout=3
                            ).json()
                            
                            wrong_answers = [
                                t['trackName'] for t in artist_query['results'] 
                                if t['trackName'] != track['trackName']
                            ]
                        except:
                            pass
                        
                        # Fill options if API didn't give enough wrong answers
                        while len(wrong_answers) < 3:
                            fallback_source = FALLBACK_SONGS[i]['options'] if i < len(FALLBACK_SONGS) else ["Option A", "Option B", "Option C"]
                            for opt in fallback_source:
                                if opt != track['trackName'] and opt not in wrong_answers:
                                    wrong_answers.append(opt)
                                if len(wrong_answers) >= 3: break
                        
                        all_options = [track['trackName']] + wrong_answers[:3]
                        random.shuffle(all_options)
                        
                        songs.append({
                            "song": track['trackName'],
                            "artist": track['artistName'],
                            "year": track.get('releaseDate', '')[:4],
                            "preview": track['previewUrl'], # The Magic Link
                            "answer": track['trackName'],
                            "options": all_options
                        })
                        success = True
            
            if not success:
                raise Exception("No preview found or API failed")

        except Exception as e:
            print(f"⚠️ API Error for '{query_term}': {e}")
            # Use Fallback if API fails
            if i < len(FALLBACK_SONGS):
                songs.append(FALLBACK_SONGS[i])
            else:
                # Generic fallback if we run out of defined fallbacks
                songs.append(FALLBACK_SONGS[0])

    return songs

@app.route('/play/guess_song')
@app.route('/play/guess_song')
def game_guess_song_play():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # [FIX] 1. Daily Lock Check
    # If the user has already played today, bounce them back to the start screen.
    today = datetime.now(timezone.utc).date().isoformat()
    stats = conn.execute("SELECT last_song_date, streak_song FROM user_stats WHERE user_id=?", (uid,)).fetchone()
    
    if stats and stats['last_song_date'] == today:
         # Pass current streak so the page doesn't crash
         current_streak = stats['streak_song'] if stats else 0
         return render_template('game_start.html', game='guess_song', stats={'streak_song': current_streak}, status='completed')

    # [FIX] 2. Ghost Cleanup
    # Clean up old sessions that never started (older than 5 minutes)
    conn.execute("""
        DELETE FROM game_sessions 
        WHERE game_type = 'guess_song' 
        AND player_1_id = ? 
        AND player_2_id IS NULL 
        AND created_at < datetime('now', '-5 minutes')
    """, (uid,))
    conn.commit()

    # 3. Find Active Session
    # Look for a game where the user is P1 or P2, and it is currently active.
    session_check = conn.execute("""
        SELECT * FROM game_sessions
        WHERE (player_1_id = ? OR player_2_id = ?)
        AND game_type = 'guess_song'
        AND status = 'active'
        ORDER BY created_at DESC LIMIT 1
    """, (uid, uid)).fetchone()

    # If no active session exists, send them to the lobby to find a match.
    if not session_check:
        return redirect(url_for('game_lobby', game='guess_song'))

    # If session exists but is waiting for a player (should be handled by lobby, but safety check)
    if not session_check['player_2_id']:
        return redirect(url_for('game_lobby', game='guess_song'))

    session_id = session_check['session_id']

    # 4. Get Partner Name
    partner_id = session_check['player_2_id'] if session_check['player_1_id'] == uid else session_check['player_1_id']
    partner = conn.execute("SELECT username FROM users WHERE user_id = ?", (partner_id,)).fetchone()
    partner_name = partner['username'] if partner else "Partner"

    # 5. Load or Fetch Game Data
    # If data isn't in the DB yet, fetch it from iTunes. Otherwise, load it.
    try:
        game_data_raw = session_check['game_data']
    except IndexError:
        game_data_raw = None

    if not game_data_raw:
        # DATA DOES NOT EXIST: Fetch new from iTunes
        print("🎵 Fetching new songs from API...")
        game_data = fetch_songs_from_itunes()
        
        # Save to database so both players see the same songs
        conn.execute("""
            UPDATE game_sessions SET game_data = ? WHERE session_id = ?
        """, (json.dumps(game_data), session_id))
        conn.commit()
    else:
        # DATA EXISTS: Load it
        try:
            game_data = json.loads(game_data_raw)
        except:
            # Fallback if JSON is corrupt
            print("Corrupt Data: Re-fetching...")
            game_data = fetch_songs_from_itunes()
            conn.execute("""
                UPDATE game_sessions SET game_data = ? WHERE session_id = ?
            """, (json.dumps(game_data), session_id))
            conn.commit()

    return render_template('guess_the_song.html',
                        session_id=session_id,
                        game_data=game_data,
                        partner_name=partner_name)

@socketio.on('submit_crossword')
def handle_crossword_submit(data):
    session_id = data.get('session_id')
    if not session_id: return

    conn = get_db()
    row = conn.execute("SELECT grid_state FROM crossword_states WHERE session_id=?", (session_id,)).fetchone()
    grid_state = json.loads(row['grid_state']) if row and row['grid_state'] else {}

    results = {}
    total_words = len(CROSSWORD_LAYOUT)
    correct_cnt = 0

    for (sr, sc), (word, direction, clue) in CROSSWORD_LAYOUT.items():
        wid = f"{sr}_{sc}_{direction}"
        is_correct = True
        for i, char in enumerate(word):
            r, c = (sr, sc + i) if direction == "across" else (sr + i, sc)
            if grid_state.get(f"{r}_{c}", '').upper() != char.upper():
                is_correct = False
                break
        
        results[wid] = {'correct': is_correct, 'answer': word}
        if is_correct: correct_cnt += 1

    # Mark complete if 100% (but don't lock)
    if correct_cnt == total_words:
        conn.execute("UPDATE game_sessions SET status='completed' WHERE session_id=?", (session_id,))
        conn.commit()

    emit('crossword_checked', {'results': results, 'all_correct': (correct_cnt == total_words)}, room=request.sid)
    
@socketio.on('song_answer_submitted')
def handle_song_answer(data):
    # 1. Validation (From your old code - Good practice)
    if not data or not isinstance(data, dict):
        return
    
    sid = data.get('session_id')
    round_num = data.get('round')
    answer = data.get('answer')
    is_correct = data.get('is_correct')
    uid = session.get('user_id')

    if not sid or round_num is None or not uid:
        return

    # 2. Store Answer (Using 'song_game_state' to match your Global Variable)
    if sid not in song_game_state:
        song_game_state[sid] = {}
    if round_num not in song_game_state[sid]:
        song_game_state[sid][round_num] = {}

    song_game_state[sid][round_num][uid] = {
        'answer': answer,
        'correct': is_correct
    }

    # 3. Check Sync Logic
    conn = get_db()
    sess = conn.execute("SELECT player_1_id, player_2_id FROM game_sessions WHERE session_id=?", (sid,)).fetchone()
    
    if sess:
        p1 = sess['player_1_id']
        p2 = sess['player_2_id']
        
        current_answers = song_game_state[sid][round_num]
        
        # If both players have answered
        if p1 in current_answers and p2 in current_answers:
            emit('both_answered', {
                'round': round_num,
                'answers': current_answers
            }, room=str(sid))
            
            # 4. Memory Cleanup (From your old code - Important!)
            # Once round is done, remove it to save memory
            try:
                del song_game_state[sid][round_num]
            except KeyError:
                pass
        else:
            # Notify the one who just answered to wait (Optional, but good for UI consistency)
            emit('waiting_for_partner', {'round': round_num}, room=request.sid)

@app.route('/play/bingo', methods=['GET', 'POST'])
def game_bingo_play():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # Handle Input
    if request.method == 'POST':
        task_id = int(request.form.get('task_id'))
        note = request.form.get('note')
        
        # Save note
        conn.execute("INSERT OR REPLACE INTO bingo_progress (user_id, task_id, note) VALUES (?, ?, ?)", (uid, task_id, note))
        conn.commit()
        
        # --- FIX 3: Check Bingo (3x3 Grid) ---
        # Get all completed tasks
        rows = conn.execute("SELECT task_id FROM bingo_progress WHERE user_id=?", (uid,)).fetchall()
        completed_ids = {r['task_id'] for r in rows}
        
        # 3x3 Winning Combinations
        # Rows: {1,2,3}, {4,5,6}, {7,8,9}
        # Cols: {1,4,7}, {2,5,8}, {3,6,9}
        # Diag: {1,5,9}, {3,5,7}
        wins = [
            {1,2,3}, {4,5,6}, {7,8,9},
            {1,4,7}, {2,5,8}, {3,6,9},
            {1,5,9}, {3,5,7}
        ]
        
        is_bingo = any(win.issubset(completed_ids) for win in wins)
        
        if is_bingo:
            update_streak(uid, 'bingo')
            flash("BINGO! You've completed a line!", "success")
            
        return redirect(url_for('game_bingo_play'))
    
    # Load Page
    rows = conn.execute("SELECT task_id, note FROM bingo_progress WHERE user_id=?", (uid,)).fetchall()
    mytasks = {r['task_id']: r['note'] for r in rows}
    
    # Fetch friends activity (Only Bingo)
    acts = conn.execute("""
        SELECT u.username, b.task_id, b.note, b.created_at 
        FROM bingo_progress b JOIN users u ON b.user_id=u.user_id 
        WHERE b.user_id != ? ORDER BY b.created_at DESC LIMIT 5
    """, (uid,)).fetchall()
    
    activity = [{'username': a['username'], 
                 'task_name': next((t['task'] for t in BINGO_TASKS if t['id']==a['task_id']),"?"), 
                 'note': a['note'], 
                 'time': a['created_at']} for a in acts]
    
    # Check if Bingo is achieved (for UI Badge)
    completed_ids = set(mytasks.keys())
    wins = [{1,2,3}, {4,5,6}, {7,8,9}, {1,4,7}, {2,5,8}, {3,6,9}, {1,5,9}, {3,5,7}]
    bingo_achieved = any(win.issubset(completed_ids) for win in wins)

    return render_template('bingo.html', 
                           tasks=BINGO_TASKS, 
                           my_tasks_map=mytasks, 
                           friends_activity=activity, 
                           bingo_achieved=bingo_achieved)

@app.route('/complete/<game_type>', methods=['POST'])
def game_complete(game_type):
    conn = get_db()
    uid = session['user_id']
    sid = request.form.get('session_id')
    
    sess = conn.execute("SELECT * FROM game_sessions WHERE session_id=?", (sid,)).fetchone()
    if not sess:
        return redirect(url_for('find_a_friend_hub'))

    if game_type == 'crossword':
        conn.execute("UPDATE game_sessions SET status='completed' WHERE session_id=?", (sid,))
        update_streak(uid, 'crossword')
    elif game_type == 'song':
        score = request.form.get('score', 0)
        conn.execute("UPDATE game_sessions SET status='completed', score=? WHERE session_id=?", (score, sid))
        update_streak(uid, 'song')
    elif game_type == 'bingo':
        # Bingo completion is handled in the play route via diagonals
        pass
        
    conn.commit()
    
    if game_type in ['crossword', 'song']:
        return redirect(url_for('game_result', session_id=sid))
    return jsonify({'status': 'success', 'message': 'Game completed!'})

@app.route('/game/result/<int:session_id>')
def game_result(session_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    # --- FIX 2: Variable Collision ---
    # Rename 'session' DB row to 'game_session' to avoid conflict with Flask 'session' cookie
    game_session = conn.execute("SELECT * FROM game_sessions WHERE session_id=?", (session_id,)).fetchone()
    
    if not game_session: return redirect(url_for('index'))
    
    pid = game_session['player_2_id'] if game_session['player_1_id'] == session['user_id'] else game_session['player_1_id']
    partner = conn.execute("SELECT * FROM users WHERE user_id=?", (pid,)).fetchone() if pid else None
    
    return render_template('game_result.html', game_session=game_session, partner=partner)

# ==========================================
# === SOCKETIO EVENTS (Real-time Logic) ===
# ==========================================


@socketio.on('join_game')
def handle_join(data):
    """Join game room"""
    session_id = str(data['session_id'])
    
    join_room(session_id)
    print(f"✅ User {session.get('username')} joined room {session_id}")
    
    # Notify others
    emit('player_joined', {
        'username': session.get('username')
    }, room=session_id, include_self=False)

@socketio.on('game_chat_message')
def handle_game_chat(data):
    """Chat messages for games"""
    if 'user_id' not in session: 
        return
    
    username = session.get('username')
    uid = session.get('user_id')
    sid = data.get('session_id')
    msg = data.get('msg', '').strip()
    
    if not msg: 
        return
    
    # Save to database
    conn = get_db()
    conn.execute("""
        INSERT INTO game_messages (session_id, user_id, content) 
        VALUES (?, ?, ?)
    """, (sid, uid, msg))
    conn.commit()
    
    # Broadcast to ENTIRE room (including sender)
    emit('game_chat_receive', {
        'user': username,
        'msg': msg,
        'timestamp': datetime.now().strftime('%H:%M')
    }, room=str(sid))

# ==========================================
# TALK NOW – LIVE CATEGORY MATCHMAKING
# ==========================================

@app.route("/talk/<category>")
def talk_matchmaking(category):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template("talk_waiting.html", category=category)


@app.route("/talk/chat/<int:session_id>")
def talk_chat(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    uid = session['user_id']

    session_check = conn.execute("""
        SELECT * FROM game_sessions
        WHERE session_id = ?
        AND game_type = 'live_chat'
        AND status = 'active'
        AND (player_1_id = ? OR player_2_id = ?)
    """, (session_id, uid, uid)).fetchone()

    if not session_check:
        return redirect(url_for("talk_matchmaking", category="Education"))

    partner_id = (
        session_check['player_2_id']
        if session_check['player_1_id'] == uid
        else session_check['player_1_id']
    )

    partner = conn.execute(
        "SELECT username FROM users WHERE user_id=?",
        (partner_id,)
    ).fetchone()

    return render_template(
        "talk_chat.html",
        session_id=session_id,
        partner_name=partner['username'] if partner else "Partner"
    )

@app.route("/talk/disconnect/<int:session_id>", methods=["POST"])
def talk_disconnect(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    conn.execute("""
        UPDATE game_sessions
        SET status = 'completed'
        WHERE session_id = ?
        AND game_type = 'live_chat'
    """, (session_id,))
    conn.commit()

    return redirect(url_for("game_start_page", game_type="talk"))

@app.route('/api/notifications/count')
def get_notification_count():
    if not session.get('user_id'):
        return jsonify({'count': 0})
    
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (session['user_id'],)).fetchone()[0]
    return jsonify({'count': count})

@app.route('/notifications')
def notifications_page():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    page = request.args.get('page', 1, type=int)
    per_page = 15
    offset = (page - 1) * per_page

    conn = get_db()

    notifications = conn.execute("""
        SELECT n.*, u.username AS actor_username
        FROM notifications n
        LEFT JOIN users u ON n.actor_id = u.user_id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
        LIMIT ? OFFSET ?
    """, (session['user_id'], per_page, offset)).fetchall()

    # Fetch pending friend requests
    friend_requests = conn.execute("""
        SELECT f.friendship_id, u.username, COALESCE(p.display_name, u.username) as display_name, f.created_at
        FROM friends f
        JOIN users u ON f.requester_id = u.user_id
        LEFT JOIN user_profiles p ON u.user_id = p.user_id
        WHERE f.addressee_id = ? AND f.status = 'pending'
        ORDER BY f.created_at DESC
    """, (session['user_id'],)).fetchall()

    total = conn.execute("""
        SELECT COUNT(*) as count
        FROM notifications
        WHERE user_id = ?
    """, (session['user_id'],)).fetchone()['count']

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'notifications.html',
        notifications=notifications,
        friend_requests=friend_requests,
        unread_count=count_unread_notifications(session['user_id']),
        page=page,
        total_pages=total_pages
    )

@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
def read_notification(notification_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE notification_id = ? AND user_id = ?", (notification_id, session['user_id']))
    conn.commit()
    
    return redirect(url_for('notifications_page'))

@app.route('/notifications/mark_all_notifications', methods=['POST'])
def mark_all_notifications():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    conn = get_db()
    conn.execute("""
        UPDATE notifications
        SET is_read = 1
        WHERE user_id = ?
    """, (session['user_id'],))
    conn.commit()

    return redirect(url_for('notifications_page'))

@app.route('/notifications/read/<int:notification_id>')
def mark_notification_read(notification_id):
    if 'user_id' not in session:
        return redirect(url_for('index'))

    conn = get_db()

    notification = conn.execute("""
        SELECT * FROM notifications
        WHERE notification_id = ? AND user_id = ?
    """, (notification_id, session['user_id'])).fetchone()

    if not notification:
        return redirect(url_for('notifications_page'))

    conn.execute("""
        UPDATE notifications
        SET is_read = 1
        WHERE notification_id = ?
    """, (notification_id,))
    conn.commit()

    return redirect(notification['link'] if notification['link'] else url_for('notifications_page'))

@app.route('/api/search_users')
def api_search_users():
    if 'user_id' not in session:
        return jsonify([]), 401
    
    query = request.args.get('q', '').strip()
    conn = get_db()
    current_uid = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()['user_id']
    
    if not query:
        # Return random suggested users if no query
        cursor = conn.execute("""
            SELECT u.username, COALESCE(up.display_name, u.username) as display_name,
                   (SELECT status FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as friend_status,
                   (SELECT requester_id FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as last_requester_id
            FROM users u
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE u.username != ?
            ORDER BY RANDOM()
            LIMIT 10
        """, (current_uid, current_uid, current_uid, current_uid, session['username']))
    else:
        # Search by username or display name
        cursor = conn.execute("""
            SELECT u.username, COALESCE(up.display_name, u.username) as display_name,
                   (SELECT status FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as friend_status,
                   (SELECT requester_id FROM friends f WHERE (f.requester_id = ? AND f.addressee_id = u.user_id) OR (f.requester_id = u.user_id AND f.addressee_id = ?) ) as last_requester_id
            FROM users u
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE (u.username LIKE ? OR COALESCE(up.display_name, u.username) LIKE ?)
            AND u.username != ?
            LIMIT 10
        """, (current_uid, current_uid, current_uid, current_uid, f'%{query}%', f'%{query}%', session['username']))
    
    users = []
    for row in cursor.fetchall():
        u = dict(row)
        # Determine specific state
        status = row['friend_status']
        requester = row['last_requester_id']
        
        u['is_friend'] = (status == 'accepted')
        u['request_sent'] = (status == 'pending' and requester == current_uid)
        u['request_received'] = (status == 'pending' and requester != current_uid)
        users.append(u)
        
    return jsonify(users)

@app.route('/api/events')
def api_events():
    conn = get_db()
    user_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()
    current_user_id = user_row['user_id']

    rows = conn.execute("""
        SELECT p.post_id, p.title, p.content,
               e.event_date, e.event_time, e.location
        FROM posts p
        JOIN event_posts e ON p.post_id = e.post_id
        JOIN event_registrations s ON s.post_id = p.post_id
        WHERE p.post_type = 'event'
        AND s.user_id = ?
        ORDER BY e.event_date, e.event_time
    """, (current_user_id,)).fetchall()

    events = []

    for row in rows:
        if row['event_time']:
            start = f"{row['event_date']}T{row['event_time']}"
        else:
            start = row['event_date']

        events.append({
            "id": str(row['post_id']),  # safer as string
            "title": row['title'],
            "start": start,
            "description": row['content'] or "",
            "location": row['location'] or "",
            "is_signed_up": True
        })

    return jsonify(events)

@app.route('/calendar')
def calendar():
    # Render the calendar page
    return render_template('calendar.html')

@app.route('/edit_profile_inline', methods=['POST'])
def edit_profile_inline():
    if 'user_id' not in session:
        flash("You must be logged in to edit your profile.", "danger")
        return redirect(url_for('index'))

    user_id = session['user_id']
    display_name = request.form.get('display_name', '').strip()
    bio = request.form.get('bio', '').strip()

    file = request.files.get('profile_pic')
    profile_pic_path = None
    if file and file.filename != '' and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"user_{user_id}_{filename}"
        os.makedirs(os.path.join(app.root_path, 'static', 'uploads'), exist_ok=True)
        save_path = os.path.join(app.root_path, 'static', 'uploads', filename)
        file.save(save_path)
        profile_pic_path = f"uploads/{filename}"

    conn = get_db()
    if profile_pic_path:
        conn.execute("""
            UPDATE user_profiles
            SET display_name = ?, bio = ?, profile_pic = ?
            WHERE user_id = ?
        """, (display_name, bio, profile_pic_path, user_id))
    else:
        conn.execute("""
            UPDATE user_profiles
            SET display_name = ?, bio = ?
            WHERE user_id = ?
        """, (display_name, bio, user_id))
    conn.commit()
    conn.close()

    flash("Profile updated!", "success")
    return redirect(url_for('userprofile', username=session.get('username')))

from datetime import datetime, timezone

def timeago(value):
    # Convert string to datetime if needed
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return value  # fallback if format is unexpected

    # Make sure datetime is timezone-aware
    now = datetime.now(timezone.utc)

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    diff = now - value
    seconds = int(diff.total_seconds())

    intervals = (
        ("year", 31536000),
        ("month", 2592000),
        ("week", 604800),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
    )

    for name, count in intervals:
        amount = seconds // count
        if amount >= 1:
            return f"{amount} {name}{'s' if amount > 1 else ''} ago"

    return "Just now"

@app.route('/play/live_chat', methods=['GET', 'POST'])
def game_live_chat_play():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    conn = get_db()

    # Ghost user protection
    if not conn.execute("SELECT 1 FROM users WHERE user_id=?", (uid,)).fetchone():
        session.clear()
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for('login'))

    # Matchmaking: find active session
    session_check = conn.execute("""
        SELECT * FROM game_sessions
        WHERE (player_1_id=? OR player_2_id=?)
        AND game_type='live_chat'
        AND status='active'
        AND player_2_id IS NOT NULL
        ORDER BY created_at DESC LIMIT 1
    """, (uid, uid)).fetchone()

    if not session_check:
        return redirect(url_for('game_lobby', game='live_chat'))

    session_id = session_check['session_id']
    partner_id = session_check['player_2_id'] if session_check['player_1_id'] == uid else session_check['player_1_id']
    partner = conn.execute("SELECT username FROM users WHERE user_id=?", (partner_id,)).fetchone()
    partner_name = partner['username'] if partner else "Partner"

    # Handle sending a message
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        if message:
            conn.execute("""
                INSERT INTO chatmessages (session_id, sender_id, receiver_id, message)
                VALUES (?, ?, ?, ?)
            """, (session_id, uid, partner_id, message))
            conn.commit()
        return redirect(url_for('game_live_chat_play'))

    # Load chat messages
    messages = conn.execute("""
        SELECT m.message, u.username AS sender_name, m.created_at
        FROM chatmessages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE m.session_id=?
        ORDER BY m.created_at ASC
    """, (session_id,)).fetchall()

    return render_template('live_chat.html',
                           session_id=session_id,
                           partner_id=partner_id,
                           partner_name=partner_name,
                           messages=messages)

@app.route('/play/live_chat/friend_request/<int:partner_id>', methods=['POST'])
def send_live_chat_friend_request(partner_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    conn = get_db()

    # Only add if not already friends
    exists = conn.execute("""
        SELECT * FROM friends
        WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)
    """, (uid, partner_id, partner_id, uid)).fetchone()

    if not exists:
        conn.execute("""
            INSERT INTO friends (requester_id, addressee_id, status, created_at)
            VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)
        """, (uid, partner_id))
        conn.commit()
        flash("Friend request sent!", "success")
    else:
        flash("You are already friends or request pending.", "info")

    return redirect(url_for('game_live_chat_play'))

@app.route('/play/live_chat/send/<int:session_id>', methods=['POST'])
def send_live_chat_message(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    message = request.form.get('message', '').strip()
    if message:
        conn = get_db()
        # Get partner_id for this session
        sess = conn.execute("SELECT player_1_id, player_2_id FROM game_sessions WHERE session_id=?", (session_id,)).fetchone()
        if not sess:
            flash("Session not found.", "error")
            return redirect(url_for('game_live_chat_play'))
        partner_id = sess['player_2_id'] if sess['player_1_id']==uid else sess['player_1_id']

        conn.execute("""
            INSERT INTO chatmessages (session_id, sender_id, receiver_id, message)
            VALUES (?, ?, ?, ?)
        """, (session_id, uid, partner_id, message))
        conn.commit()

    return redirect(url_for('game_live_chat_play'))

@app.route('/play/live_chat/leave/<int:session_id>', methods=['POST'])
def leave_live_chat(session_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    uid = session['user_id']
    conn = get_db()

    # Remove the user from the session
    session_row = conn.execute("SELECT * FROM game_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not session_row:
        flash("Session not found.", "warning")
        return redirect(url_for('game_lobby', game='live_chat'))

    # If the user is player_1 or player_2, mark session inactive
    if session_row['player_1_id'] == uid or session_row['player_2_id'] == uid:
        conn.execute("UPDATE game_sessions SET status='inactive' WHERE session_id=?", (session_id,))
        conn.commit()

    flash("You left the chat.", "info")
    return redirect(url_for('game_lobby', game='live_chat'))


@socketio.on('live_chat_message')
def handle_live_chat_message(data):
    uid = data.get('user_id')  # <- get from client
    session_id = data.get('session_id')
    message = data.get('message', '').strip()
    if not message or not uid or not session_id:
        return

    conn = get_db()
    chat_sess = conn.execute("SELECT player_1_id, player_2_id FROM game_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not chat_sess:
        return

    receiver_id = chat_sess['player_2_id'] if chat_sess['player_1_id']==uid else chat_sess['player_1_id']

    conn.execute("""
        INSERT INTO chatmessages (session_id, sender_id, receiver_id, message, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (session_id, uid, receiver_id, message))
    conn.commit()

    emit('new_live_message', {
        'session_id': session_id,
        'sender_id': uid,
        'sender_name': data.get('sender_name', 'Unknown'),
        'message': message,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }, room=str(session_id))

@socketio.on('join')
def on_join(data):
    room = str(data.get('room'))
    join_room(room)

@app.route('/friend/request/<username>', methods=['POST'])
def send_friend_request_live(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()

    requester_id = conn.execute(
        "SELECT user_id FROM users WHERE username=?",
        (session['username'],)
    ).fetchone()['user_id']

    target = conn.execute(
        "SELECT user_id FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not target:
        return "User not found"

    try:
        conn.execute("""
            INSERT INTO friends (requester_id, addressee_id, status)
            VALUES (?, ?, 'pending')
        """, (requester_id, target['user_id']))
        conn.commit()
        
        # Notify the recipient
        create_notification(
            user_id=target['user_id'],
            actor_id=requester_id,
            notif_type='friend_request',
            message=f"{session['username']} sent you a friend request",
            link=url_for('notifications_page'), # Redirect to notifications page to accept/decline
            reference_id=requester_id # using reference_id as the requester_id can be useful
        )
        
    except sqlite3.IntegrityError:
        pass  # already exists

    return redirect(url_for('live_chat', username=username))

# Register the filter
app.jinja_env.filters["timeago"] = timeago

# --- Main ---
if __name__ == "__main__":
    init_db()
    # FIX: use_reloader=False prevents the WinError 10038 crash
    socketio.run(app, debug=True) 