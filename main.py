# imports
import sqlite3
import requests
import json
from flask import Flask, render_template, session, redirect, url_for, request, g, flash, jsonify
from flask_socketio import SocketIO, emit

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import date, datetime, timedelta, time
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
socketio = SocketIO(app, manage_session=False)
app.jinja_env.filters['mention'] = mention

# Dictionary to track online users: username -> sid
online_users = {}

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
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite3_db'):
        g.sqlite3_db.close()

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
    
    # 1. Get user_id safely. 
    # If it's not in the session, try to find it via the username.
    user_id = session.get('user_id')
    if not user_id and 'username' in session:
        user_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()
        if user_row:
            user_id = user_row['user_id']
            session['user_id'] = user_id  # Save it to session so we don't have to look it up again

    # 2. Execute the query with the user_liked check
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
        ORDER BY posts.created_at DESC
    """, (user_id,)).fetchall()
    
    return render_template('index.html', posts=posts)
# Community page
@app.route('/community/<int:community_id>')
def community(community_id):
    conn = get_db()
    current_user_id = session.get('user_id')
    is_member = False

    # 1. Self-heal session: If we have a username but no user_id, fetch it
    if not current_user_id and 'username' in session:
        user_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()
        if user_row:
            current_user_id = user_row['user_id']
            session['user_id'] = current_user_id # Persist it for future requests

    # 2. Check membership
    if current_user_id:
        is_member = conn.execute(
            "SELECT 1 FROM community_members WHERE user_id = ? AND community_id = ?",
            (current_user_id, community_id)
        ).fetchone() is not None

    # 3. Get community details
    community_row = conn.execute(
        "SELECT * FROM communities WHERE community_id = ?",
        (community_id,)
    ).fetchone()
    
    if not community_row:
        return "Community not found", 404

    # 4. Fetch posts with Like Count and User Liked status
    # We pass current_user_id to the subquery to determine the heart color
    posts = conn.execute("""
        SELECT p.*, u.username,
               (SELECT COUNT(*) FROM post_likes WHERE post_id = p.post_id) AS like_count,
               (SELECT 1 FROM post_likes WHERE post_id = p.post_id AND user_id = ?) AS user_liked
        FROM posts p
        JOIN users u ON p.user_id = u.user_id 
        WHERE p.community_id = ?
        ORDER BY p.created_at DESC
    """, (current_user_id, community_id)).fetchall()

    return render_template('community.html', community=community_row, posts=posts, is_member=is_member)
import time # Ensure this is at the top with your other imports

# --- View Post + Comments (AJAX Integrated) ---
@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def openpost(post_id):
    conn = get_db()
    username = session.get('username')

    # --- Fetch post + event info ---
    post = conn.execute("""
        SELECT p.*, 
               e.location, e.event_date, e.event_time, e.organiser_id,
               u.username AS creator_username,
               c.community_id, c.name AS community_name,
               org.username AS organiser_username
        FROM posts p
        JOIN users u ON p.user_id = u.user_id
        JOIN communities c ON p.community_id = c.community_id
        LEFT JOIN event_posts e ON p.post_id = e.post_id
        LEFT JOIN users org ON e.organiser_id = org.user_id
        WHERE p.post_id = ?
    """, (post_id,)).fetchone()

    if not post:
        return "Post not found.", 404

    post_dict = dict(post)
    post_dict['username'] = post_dict['organiser_username'] if post_dict['post_type'] == 'event' and post_dict['organiser_username'] else post_dict['creator_username']

    # --- Handle POST requests ---
    if request.method == 'POST':
        if not username:
            return redirect(url_for('login'))

        user_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()
        if not user_row:
            return redirect(url_for('login'))

        user_id = user_row['user_id']

        # --- Event registration ---
        if 'register_event' in request.form:
            result = conn.execute("""
                SELECT 1 FROM event_registrations
                WHERE post_id = ? AND user_id = ?
            """, (post_id, user_id)).fetchone()

            if not result:
                conn.execute("""
                    INSERT INTO event_registrations (post_id, user_id)
                    VALUES (?, ?)
                """, (post_id, user_id))
                conn.commit()

            return redirect(url_for('openpost', post_id=post_id))

        # --- Comment submission ---
        content = request.form.get('content', '').strip()
        if content:
            conn.execute(
                "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
                (post_id, user_id, content)
            )
            conn.commit()

            # --- Create notification ---
            post_owner_id = post_dict['user_id']
            if post_dict['post_type'] == 'event' and post_dict['organiser_id']:
                post_owner_id = post_dict['organiser_id']

            if post_owner_id != user_id:
                create_notification(
                    user_id=post_owner_id,
                    actor_id=user_id,
                    notif_type="comment",
                    message=f"{username} commented on your post",
                    link=url_for('openpost', post_id=post_id),
                    reference_id=post_id
                )

            return redirect(url_for('openpost', post_id=post_id))

    # --- Fetch comments ---
    comments = conn.execute("""
        SELECT c.comment_id, c.content, c.created_at, u.username
        FROM comments c
        JOIN users u ON c.user_id = u.user_id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC
    """, (post_id,)).fetchall()

    # --- Check if current user is registered for the event ---
    is_registered = False
    if session.get('user_id') and post_dict['post_type'] == 'event':
        result = conn.execute("""
            SELECT 1 FROM event_registrations
            WHERE post_id = ? AND user_id = ?
        """, (post_id, session['user_id'])).fetchone()
        is_registered = bool(result)

    return render_template(
        'openpost.html',
        post=post_dict,
        comments=comments,
        is_registered=is_registered
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
        
        # A. Delete Likes on all Comments belonging to this post
        conn.execute('''
            DELETE FROM comment_likes 
            WHERE comment_id IN (SELECT comment_id FROM comments WHERE post_id = ?)
        ''', (post_id,))
        
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


#@app.route('/delete_comment/<int:post_id>', methods=['POST'])
def delete_comment(post_id):
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    conn = get_db()
    
    # Get user_id
    user = conn.execute("SELECT user_id FROM users WHERE username = ?", (session['username'],)).fetchone()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    user_id = user['user_id']

    # Get the latest comment by this user for this post
    comment = conn.execute("""
        SELECT comment_id FROM comments 
        WHERE post_id = ? AND user_id = ? 
        ORDER BY created_at DESC LIMIT 1
    """, (post_id, user_id)).fetchone()

    if not comment:
        return jsonify({'status': 'error', 'message': 'No comment found to delete'}), 404

    # Delete likes first
    conn.execute('DELETE FROM comment_likes WHERE comment_id = ?', (comment['comment_id'],))
    # Delete comment
    conn.execute('DELETE FROM comments WHERE comment_id = ?', (comment['comment_id'],))
    conn.commit()

    return jsonify({'status': 'success'})

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
        return {"status": "error", "message": "Unauthorized"}, 401
    
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
        
        # Get the new total like count for this specific comment
        count_row = conn.execute(
            "SELECT COUNT(*) FROM comment_likes WHERE comment_id = ?", 
            (comment_id,)
        ).fetchone()
        new_count = count_row[0] if count_row else 0
        
        return {
            "status": "success", 
            "liked": liked, 
            "new_count": new_count
        }

    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}, 500

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
# Register
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
        return redirect(url_for("index"))

    except sqlite3.IntegrityError:
        # Trigger modal with flash
        flash("Username or email already exists", "register_error")
        return redirect(url_for("index"))
    
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

    if not user or not check_password_hash(user["password"], password):
        flash("Invalid username or password", "login_error")
        return redirect(url_for("index"))

    # 1. Wipe any old session data (ghost users)
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

# User profile
@app.route('/userprofile/<username>')
def userprofile(username):
    conn = get_db()

    # 1. Get the ID of the person CURRENTLY logged in (to check for likes)
    # If not logged in, we set it to 0 or None so the subqueries don't crash
    viewer_id = session.get('user_id', 0) 

    # --- Profile info ---
    profile = conn.execute("""
        SELECT u.user_id, u.username, u.email, u.phone, u.age,
               p.display_name, p.bio
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

    # --- Comments by user (INNER JOIN ensures post must exist) ---
    # This automatically hides comments on deleted posts!
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

    return render_template(
        'userprofile.html',
        profile=profile,
        communities=user_communities,
        posts=posts,
        comments=comments
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

    # recipient
    other_user = conn.execute("""
        SELECT u.user_id, u.username, p.display_name
        FROM users u
        JOIN user_profiles p ON u.user_id=p.user_id
        WHERE u.username=?
    """, (username,)).fetchone()
    if not other_user:
        return "User not found"

    # new message
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            conn.execute(
                "INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)",
                (current_user_id, other_user['user_id'], content)
            )
            conn.commit()
        return redirect(url_for('chat', username=username))

    # get all messages
    messages = conn.execute("""
        SELECT m.content, m.created_at, u.username AS sender_username
        FROM messages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE (m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)
        ORDER BY m.created_at ASC
    """, (current_user_id, other_user['user_id'], other_user['user_id'], current_user_id)).fetchall()

    # list of users tht u hv talked to, needs to integrate friends Bruhh
    chats_query = conn.execute("""
        SELECT DISTINCT u.user_id, u.username, p.display_name,
               (SELECT content 
                FROM messages 
                WHERE (sender_id=? AND recipient_id=u.user_id) OR (sender_id=u.user_id AND recipient_id=?)
                ORDER BY created_at DESC LIMIT 1
               ) AS last_message
        FROM users u
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.user_id IN (
            SELECT sender_id FROM messages WHERE recipient_id=?
            UNION
            SELECT recipient_id FROM messages WHERE sender_id=?
            UNION
            SELECT contact_user_id FROM contacts WHERE user_id=?
        )
    """, (current_user_id, current_user_id, current_user_id, current_user_id, current_user_id)).fetchall()

    chats_list = []
    for c in chats_query:
        chats_list.append({
            'username': c['username'],
            'display_name': c['display_name'],
            'last_message': c['last_message'] if c['last_message'] else "",
            'online': c['username'] in online_users
        })

    # --- UPDATED: FETCH GROUP CHATS ---
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
        groups=groups_query, # Pass groups to template
        current_chat=other_user
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
    if not sender_username or not msg or not recipient_username:
        return

    conn = get_db()
    sender_id = conn.execute("SELECT user_id FROM users WHERE username = ?", (sender_username,)).fetchone()['user_id']
    recipient_row = conn.execute("SELECT user_id FROM users WHERE username = ?", (recipient_username,)).fetchone()
    if not recipient_row:
        return
    recipient_id = recipient_row['user_id']

    conn.execute("INSERT INTO messages (sender_id, recipient_id, content) VALUES (?, ?, ?)",
                 (sender_id, recipient_id, msg))
    
    conn.commit()

    # real time text
    recipient_sid = online_users.get(recipient_username)
    if recipient_sid:
        emit('message', {'user': sender_username, 'msg': msg}, room=recipient_sid)
    emit('message', {'user': sender_username, 'msg': msg}, room=request.sid) 

@socketio.on('send_group_message')
def handle_group_message(data):
    sender_username = session.get('username')
    msg = data.get('msg')
    group_id = data.get('group_id')
    
    if not sender_username or not msg or not group_id:
        return
    
    conn = get_db()
    sender_id = conn.execute("SELECT user_id FROM users WHERE username = ?", (sender_username,)).fetchone()['user_id']
    
    # Insert message
    conn.execute(
        "INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)",
        (group_id, sender_id, msg)
    )
    conn.commit()
    
    # Broadcast to all group members
    emit('group_message', {
        'user': sender_username,
        'msg': msg,
        'group_id': group_id,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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

#
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

    conn.commit()
    return redirect(url_for('index'))

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
    chats_query = conn.execute("""
        SELECT DISTINCT u.user_id, u.username, p.display_name,
               (SELECT content 
                FROM messages 
                WHERE (sender_id = ? AND recipient_id = u.user_id)
                   OR (sender_id = u.user_id AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1
               ) AS last_message,
               (SELECT MAX(created_at) FROM messages m2
                WHERE (m2.sender_id = u.user_id AND m2.recipient_id = ?)
                   OR (m2.sender_id = ? AND m2.recipient_id = u.user_id)
               ) AS last_message_time
        FROM users u
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.user_id IN (
            -- Users from message history
            SELECT sender_id FROM messages WHERE recipient_id = ?
            UNION
            SELECT recipient_id FROM messages WHERE sender_id = ?
            UNION
            -- Users from contacts
            SELECT contact_user_id FROM contacts WHERE user_id = ?
        )
        ORDER BY last_message_time DESC NULLS LAST, p.display_name ASC
    """, (current_user_id, current_user_id, current_user_id, current_user_id, current_user_id, current_user_id, current_user_id)).fetchall()

    # list of dictionary
    chats = []
    for row in chats_query:
        chats.append({
            'user_id': row['user_id'],
            'username': row['username'],
            'display_name': row['display_name'],
            'last_message': row['last_message'] if row['last_message'] else "",
            'online': row['username'] in online_users
        })

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

    return render_template(
        'chat_private.html',
        messages=messages,
        chats=chats,
        groups=groups_query, # Pass groups
        current_chat=current_chat,
        recipient=current_chat  # Remmeber  this
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
    
    chats_query = conn.execute("""
        SELECT DISTINCT u.user_id, u.username, p.display_name,
               (SELECT content 
                FROM messages 
                WHERE (sender_id = ? AND recipient_id = u.user_id)
                   OR (sender_id = u.user_id AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1
               ) AS last_message,
               (SELECT MAX(created_at) FROM messages m2
                WHERE (m2.sender_id = u.user_id AND m2.recipient_id = ?)
                   OR (m2.sender_id = ? AND m2.recipient_id = u.user_id)
               ) AS last_message_time
        FROM users u
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.user_id IN (
            SELECT sender_id FROM messages WHERE recipient_id = ?
            UNION
            SELECT recipient_id FROM messages WHERE sender_id = ?
            UNION
            SELECT contact_user_id FROM contacts WHERE user_id = ?
        )
        ORDER BY last_message_time DESC NULLS LAST, p.display_name ASC
    """, (current_user_id, current_user_id, current_user_id, current_user_id, current_user_id, current_user_id, current_user_id)).fetchall()
    
    chats = []
    for row in chats_query:
        chats.append({
            'user_id': row['user_id'],
            'username': row['username'],
            'display_name': row['display_name'],
            'last_message': row['last_message'] if row['last_message'] else "",
            'online': row['username'] in online_users
        })
    

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
        SELECT gm.content, gm.created_at, u.username AS sender_username, p.display_name
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
        'messages': [{'content': m['content'], 'sender_username': m['sender_username'], 'display_name': m['display_name'], 'created_at': m['created_at']} for m in messages],
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

# Explore page - show all communities except the ones user is already in

# ==========================================
# === FIND A FRIEND & GAMES (Phoebe) ===
# ==========================================

# --- 1. Game Data ---
BINGO_TASKS = [
    {"id": 1, "task": "Drank Milo"}, {"id": 2, "task": "5 min walk"},
    {"id": 3, "task": "Ate Hawker Meal"}, {"id": 4, "task": "Called a friend"},
    {"id": 5, "task": "Read News"}, {"id": 6, "task": "Watered Plants"},
    {"id": 7, "task": "Used Dialect"}, {"id": 8, "task": "Listened to Radio"},
    {"id": 9, "task": "Slept by 10pm"}
]

MUSIC_ROUNDS = [
    {"search": "Deja Vu Tomorrow X Together", "answer": "Deja Vu", "options": ["Beautiful Strangers", "Deja Vu", "Chasing That Feeling", "Love Language"]},
    {"search": "It Must Have Been Love Roxette", "answer": "It Must Have Been Love", "options": ["Listen to Your Heart", "It Must Have Been Love", "The Look", "Joyride"]},
    {"search": "Chk Chk Boom Stray Kids", "answer": "Chk Chk Boom", "options": ["Chk Chk Boom", "Megaverse", "Do It", "LALALALA"]},
    {"search": "Dancing Queen ABBA", "answer": "Dancing Queen", "options": ["Mamma Mia", "Dancing Queen", "Super Trouper", "Waterloo"]},
    {"search": "Easier 5 Seconds of Summer", "answer": "Easier", "options": ["Easier", "A Different Way", "Entertainer", "Youngblood"]}
]

CROSSWORD_LAYOUT = {
    (4, 3): 'T', (4, 4): 'O', (4, 5): 'M', (4, 6): 'O', (4, 7): 'R', (4, 8): 'R', (4, 9): 'O', (4, 10): 'W', (4, 11): 'X', (4, 12): 'T', (4, 13): 'O', (4, 14): 'G', (4, 15): 'E', (4, 16): 'T', (4, 17): 'H', (4, 18): 'E', (4, 19): 'R',
    (2, 5): 'D', (3, 5): 'R', (4, 5): 'E', (5, 5): 'A', (6, 5): 'M',
    (4, 9): 'M', (5, 9): 'O', (6, 9): 'A',
    (8, 6): 'B', (8, 7): 'I', (8, 8): 'G', (8, 9): 'H', (8, 10): 'I', (8, 11): 'T',
    (7, 11): 'T', (8, 11): 'X', (9, 11): 'T'
}

# --- 2. Helper Functions ---
def update_streak(user_id, game):
    conn = get_db()
    stats = conn.execute("SELECT * FROM user_stats WHERE user_id=?", (user_id,)).fetchone()
    today = date.today().isoformat()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    
    col_streak, col_date = f"streak_{game}", f"last_{game}_date"
    current = stats[col_streak] if stats else 0
    last = stats[col_date] if stats else None
    
    if last == today: return
    new_streak = current + 1 if last == yesterday else 1
    
    if stats: conn.execute(f"UPDATE user_stats SET {col_streak}=?, {col_date}=? WHERE user_id=?", (new_streak, today, user_id))
    else: conn.execute(f"INSERT INTO user_stats (user_id, {col_streak}, {col_date}) VALUES (?, ?, ?)", (user_id, new_streak, today))
    conn.commit()

# NEW: Priority Matchmaking Logic (Youth < 30, Elderly > 50)
def find_match_priority(conn, user_id, game_type):
    # Get my age
    user = conn.execute("SELECT age FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if not user: return None
    my_age = user['age']

    # Define Generations
    is_youth = my_age < 30
    is_elderly = my_age > 50
    
    target_condition = ""
    # Cross-generational matching logic
    if is_youth:
        target_condition = "AND u.age > 50" # Youth looks for Elderly
    elif is_elderly:
        target_condition = "AND u.age < 30" # Elderly looks for Youth
    
    today = date.today().isoformat()
    
    # Attempt 1: Find Priority Match
    if target_condition:
        query = f"""
            SELECT s.session_id, s.player_1_id 
            FROM game_sessions s
            JOIN users u ON s.player_1_id = u.user_id
            WHERE s.game_type=? 
            AND s.player_2_id IS NULL 
            AND s.status='active' 
            AND date(s.created_at)=? 
            AND s.player_1_id != ? 
            {target_condition}
        """
        match = conn.execute(query, (game_type, today, user_id)).fetchone()
        if match: return match

    # Attempt 2: If no priority match (or middle-aged), find ANY match (FIFO)
    return conn.execute("""
        SELECT session_id, s.player_1_id 
        FROM game_sessions s
        WHERE s.game_type=? AND s.player_2_id IS NULL 
        AND s.status='active' AND date(s.created_at)=? 
        AND s.player_1_id != ?
    """, (game_type, today, user_id)).fetchone()

# --- 3. Game Routes ---

@app.route('/find-a-friend')
def find_a_friend_hub():
    if 'username' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # Get stats for the dashboard
    stats = conn.execute("SELECT * FROM user_stats WHERE user_id=?", (uid,)).fetchone()
    if not stats:
        stats = {'streak_bingo': 0, 'streak_crossword': 0, 'streak_song': 0}

    return render_template('find_a_friend.html', stats=stats)

# NEW: Start Page (Pre-Lobby)
@app.route('/game/start/<game_type>')
def game_start_page(game_type):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # Get My Stats
    stats = conn.execute("SELECT * FROM user_stats WHERE user_id=?", (uid,)).fetchone()
    if not stats: stats = {'streak_bingo':0, 'streak_crossword':0, 'streak_song':0}
    
    # Get Friends Activity (Excluding Me)
    activity = conn.execute("""
        SELECT u.username, b.note, b.created_at, b.task_id 
        FROM bingo_progress b 
        JOIN users u ON b.user_id = u.user_id 
        WHERE b.user_id != ? 
        ORDER BY b.created_at DESC LIMIT 5
    """, (uid,)).fetchall()
        
    return render_template('game_start.html', game=game_type, stats=stats, activity=activity)

@app.route('/lobby/<game>')
def game_lobby(game):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # 1. Try to find a match using PRIORITY logic
    match = find_match_priority(conn, uid, game)
    
    if match:
        sid = match['session_id']
        conn.execute("UPDATE game_sessions SET player_2_id=? WHERE session_id=?", (uid, sid))
        conn.commit()
        return redirect(url_for(f'game_{game}_play'))
        
    # 2. No match? Create new session and wait
    existing = conn.execute("SELECT session_id FROM game_sessions WHERE game_type=? AND player_1_id=? AND status='active'", (game, uid)).fetchone()
    if not existing:
        conn.execute("INSERT INTO game_sessions (game_type, player_1_id) VALUES (?, ?)", (game, uid))
        conn.commit()
    
    return render_template('lobby.html', game=game)

@app.route('/play/crossword')
def game_crossword_play():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    # 1. Check for active game (Either Player 1 or Player 2)
    active = conn.execute("SELECT session_id, player_1_id, player_2_id FROM game_sessions WHERE game_type='crossword' AND (player_1_id=? OR player_2_id=?) AND status='active'", (uid, uid)).fetchone()

    if active:
        sid = active['session_id']
        pid = active['player_2_id'] if active['player_1_id'] == uid else active['player_1_id']
        
        partner_name = "Waiting..."
        if pid:
            u = conn.execute("SELECT username FROM users WHERE user_id=?", (pid,)).fetchone()
            if u: partner_name = u['username']

        # Get Saved Moves
        letters = conn.execute("SELECT row, col, letter FROM crossword_state WHERE session_id=?", (sid,)).fetchall()
        current_state = {f"{r['row']}_{r['col']}": r['letter'] for r in letters}

        # Determine Role
        is_p1 = (active['player_1_id'] == uid)
        my_role = 'p1' if is_p1 else 'p2'

        return render_template('crossword.html', 
                               session_id=sid, 
                               layout=CROSSWORD_LAYOUT, 
                               current_state=current_state, 
                               partner_name=partner_name,
                               my_role=my_role)
    else:
        # NO Active Game? Redirect to Lobby to find one
        return redirect(url_for('game_lobby', game='crossword'))

@app.route('/play/guess_song')
def game_guess_song_play():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    active = conn.execute("SELECT session_id, player_1_id, player_2_id FROM game_sessions WHERE game_type='guess_song' AND (player_1_id=? OR player_2_id=?) AND status='active'", (uid, uid)).fetchone()
    
    if active:
        sid = active['session_id']
        pid = active['player_2_id'] if active['player_1_id']==uid else active['player_1_id']
        pname = conn.execute("SELECT username FROM users WHERE user_id=?", (pid,)).fetchone()['username'] if pid else "Waiting..."
        
        gdata = []
        for r in MUSIC_ROUNDS:
            preview_url = None
            try:
                res = requests.get(f"https://itunes.apple.com/search?term={quote(r['search'])}&media=music&limit=1", timeout=2).json()
                if res['resultCount'] > 0:
                    preview_url = res['results'][0]['previewUrl']
            except:
                pass 
            gdata.append({"preview": preview_url, "answer": r['answer'], "options": r['options']})
            
        return render_template('guess_the_song.html', game_data=gdata, readonly=False, partner_name=pname, session_id=sid)
    else:
        # NO Active Game? Redirect to Lobby
        return redirect(url_for('game_lobby', game='guess_song'))

@app.route('/play/bingo', methods=['GET', 'POST'])
def game_bingo_play():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    uid = session['user_id']
    
    if request.method == 'POST':
        task_id = request.form.get('task_id')
        note = request.form.get('note')
        
        # Check if already done (Prevent duplicates)
        exists = conn.execute("SELECT 1 FROM bingo_progress WHERE user_id=? AND task_id=?", (uid, task_id)).fetchone()
        
        if not exists:
            conn.execute("INSERT INTO bingo_progress (user_id, task_id, note) VALUES (?, ?, ?)", (uid, task_id, note))
            # UPDATE STREAK on completion
            update_streak(uid, 'bingo')
            conn.commit()
            
        return redirect(url_for('game_bingo_play'))
    
    rows = conn.execute("SELECT task_id, note FROM bingo_progress WHERE user_id=?", (uid,)).fetchall()
    mytasks = {r['task_id']: r['note'] for r in rows}
    
    # Activity: Filtered to exclude ME (WHERE b.user_id != ?)
    acts = conn.execute("""
        SELECT u.username, b.task_id, b.note, b.created_at 
        FROM bingo_progress b 
        JOIN users u ON b.user_id=u.user_id 
        WHERE b.user_id != ? 
        ORDER BY b.created_at DESC LIMIT 5
    """, (uid,)).fetchall()
    
    activity = [{'username': a['username'], 'task_name': next((t['task'] for t in BINGO_TASKS if t['id']==a['task_id']),"?"), 'note': a['note'], 'time': a['created_at']} for a in acts]
    
    return render_template('bingo.html', tasks=BINGO_TASKS, my_tasks_map=mytasks, friends_activity=activity)

@app.route('/complete/<game_type>', methods=['POST'])
def game_complete(game_type):
    conn = get_db()
    uid = session['user_id']
    sid = request.form.get('session_id')
    
    if game_type == 'crossword':
        conn.execute("UPDATE game_sessions SET status='completed' WHERE session_id=?", (sid,))
        update_streak(uid, 'crossword')
    elif game_type == 'song':
        score = request.form.get('score', 0)
        conn.execute("UPDATE game_sessions SET status='completed', score=? WHERE session_id=?", (score, sid))
        update_streak(uid, 'song')
    elif game_type == 'bingo':
        update_streak(uid, 'bingo')
        
    conn.commit()
    
    if game_type in ['crossword', 'song']:
        return redirect(url_for('game_result', session_id=sid))
    return redirect(url_for('find_a_friend_hub'))

@app.route('/game/result/<int:session_id>')
def game_result(session_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db()
    sess = conn.execute("SELECT * FROM game_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not sess: return redirect(url_for('index'))

    pid = sess['player_2_id'] if sess['player_1_id'] == session['user_id'] else sess['player_1_id']
    partner = conn.execute("SELECT * FROM users WHERE user_id=?", (pid,)).fetchone() if pid else None

    return render_template('game_result.html', session=sess, partner=partner)
# Explore page - show all communities except the ones user is already in
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

    total = conn.execute("""
        SELECT COUNT(*) as count
        FROM notifications
        WHERE user_id = ?
    """, (session['user_id'],)).fetchone()['count']

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        'notifications.html',
        notifications=notifications,
        page=page,
        total_pages=total_pages
    )

@app.route('/notifications/mark_all_notifications')
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
#==========================================
# === SOCKETIO EVENTS (Real-time Logic) ===
# ==========================================

@socketio.on('join_game')
def handle_join(data): 
    from flask_socketio import join_room
    join_room(str(data['session_id']))
    # Notify that game is starting for song game sync
    emit('start_song_game', {}, room=str(data['session_id']))

@socketio.on('crossword_move')
def handle_cw_move(data):
    if 'user_id' not in session: return
    
    # Save the move to DB
    with sqlite3.connect(DATABASE) as sql:
        sql.execute("INSERT OR REPLACE INTO crossword_state (session_id, row, col, letter, updated_by) VALUES (?, ?, ?, ?, ?)", 
                    (data['session_id'], data['row'], data['col'], data['letter'].upper(), session['user_id']))
        sql.commit()
    
    # Check if correct (Simple check)
    is_correct = False
    target_char = CROSSWORD_LAYOUT.get((int(data['row']), int(data['col'])))
    if target_char and target_char == data['letter'].upper():
        is_correct = True
        
    # Broadcast to partner
    emit('update_grid', {
        'row': data['row'], 
        'col': data['col'], 
        'letter': data['letter'].upper(),
        'is_correct': is_correct
    }, room=str(data['session_id']))

@socketio.on('game_chat_message')
def handle_game_chat(data):
    username = session.get('username')
    msg = data.get('msg')
    sid = data.get('session_id')
    emit('game_chat_receive', {'user': username, 'msg': msg}, room=str(sid))@app.route('/notifications')

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

# --- Main ---
if __name__ == "__main__":
    init_db()
    # FIX: use_reloader=False prevents the WinError 10038 crash
    socketio.run(app, debug=True,allow_unsafe_werkzeug=True, use_reloader=True) 