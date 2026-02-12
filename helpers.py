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
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


DATABASE = 'database.db'
# --- Database Functions ---
def init_db():
    conn = sqlite3.connect(DATABASE)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,            -- receiver
        actor_id INTEGER,
        type TEXT NOT NULL,
        reference_id INTEGER,
        message TEXT NOT NULL,
        link TEXT,
        is_read INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
        FOREIGN KEY(actor_id) REFERENCES users(user_id) ON DELETE CASCADE
    )
    """)

    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(user_id, is_read)")

    # users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            age INT NOT NULL
        )
    """)

    # 1. ADD THE LIKES TABLE
    conn.execute("""
        CREATE TABLE IF NOT EXISTS post_likes (
            like_id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            UNIQUE(post_id, user_id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS comment_likes (
            like_id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(comment_id) REFERENCES comments(comment_id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            UNIQUE(comment_id, user_id)
        )
    """)

    # 2. SCHEMA MIGRATION: Fix missing columns in posts table
    # Since you took your teammates' database, it might be missing these.
    # We use a try/except block so it doesn't crash if they already exist.
    try:
        conn.execute("ALTER TABLE posts ADD COLUMN image_url TEXT")
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute("ALTER TABLE posts ADD COLUMN post_type TEXT DEFAULT 'general'")
    except sqlite3.OperationalError:
        pass  # Column already exists

    # user profiles table [for display]
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY,
            display_name TEXT NOT NULL,
            bio TEXT,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    # communities table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS communities (
            community_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    """)

# posts table (Updated to include image_url and post_type)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            post_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            community_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT,
            image_url TEXT,
            post_type TEXT DEFAULT 'general',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY(community_id) REFERENCES communities(community_id) ON DELETE CASCADE
        )
    """)

    # event_posts table (1:1 relationship with posts)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS event_posts (
            post_id INTEGER PRIMARY KEY,         -- same ID as posts table
            organiser_id INTEGER NOT NULL,       -- defaults to post creator
            location TEXT,
            event_date DATE,
            event_time TIME,
            FOREIGN KEY(post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
            FOREIGN KEY(organiser_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    # 3. SCHEMA MIGRATION FOR E2EE
    try:
        conn.execute("ALTER TABLE users ADD COLUMN public_key TEXT")
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute("ALTER TABLE messages ADD COLUMN is_encrypted INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute("ALTER TABLE group_messages ADD COLUMN is_encrypted INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass


    # comments table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    # messages table for private chat
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sender_id) REFERENCES users(user_id),
            FOREIGN KEY(recipient_id) REFERENCES users(user_id)
        )
    """)

    # community memberships [intersection table between communities and members]
    conn.execute("""
        CREATE TABLE IF NOT EXISTS community_members (
            user_id INTEGER NOT NULL,
            community_id INTEGER NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, community_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (community_id) REFERENCES communities(community_id) ON DELETE CASCADE
        )
    """)

    #friends table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            friendship_id INTEGER PRIMARY KEY AUTOINCREMENT,

            requester_id INTEGER NOT NULL,
            addressee_id INTEGER NOT NULL,

            status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'blocked')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            responded_at DATETIME,

            UNIQUE (requester_id, addressee_id),

            FOREIGN KEY (requester_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (addressee_id) REFERENCES users(user_id) ON DELETE CASCADE,

            CHECK (requester_id != addressee_id)
        )

    """)
    
   # Game Stats (Streaks)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_stats (
            user_id INTEGER PRIMARY KEY,
            streak_bingo INTEGER DEFAULT 0, last_bingo_date TEXT,
            streak_crossword INTEGER DEFAULT 0, last_crossword_date TEXT,
            streak_song INTEGER DEFAULT 0, last_song_date TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        )
    """)

    # Game Sessions (Lobby)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS game_sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_type TEXT NOT NULL,
            player_1_id INTEGER NOT NULL,
            player_2_id INTEGER,
            status TEXT DEFAULT 'active',
            score INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Crossword State
    conn.execute("""
        CREATE TABLE IF NOT EXISTS crossword_state (
            session_id INTEGER NOT NULL,
            row INTEGER NOT NULL,
            col INTEGER NOT NULL,
            letter TEXT NOT NULL,
            updated_by INTEGER NOT NULL,
            PRIMARY KEY (session_id, row, col)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS live_category_queue (
            queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id),
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)


    # Bingo Progress
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bingo_progress (
            user_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            note TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, task_id)
        )
    """)
    
    # contacts table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            contact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            contact_name TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (user_id, contact_user_id),
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY(contact_user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            CHECK (user_id != contact_user_id)
        )
    """)
    
    # group chats table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS group_chats (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            creator_id INTEGER NOT NULL,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(creator_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    
    # group members table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            member_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (group_id, user_id),
            FOREIGN KEY(group_id) REFERENCES group_chats(group_id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    
    # group messages table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS group_messages (
            message_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(group_id) REFERENCES group_chats(group_id) ON DELETE CASCADE,
            FOREIGN KEY(sender_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)
    # Event registrations table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS event_registrations (
            registration_id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(post_id, user_id),
            FOREIGN KEY(post_id) REFERENCES posts(post_id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    
    conn.commit()
    conn.close()

def mention(text):
    if not text:
        return text
    
    # Escape original text to prevent XSS
    escaped_text = str(escape(text))
    
    # Find all potential @usernames
    potential_mentions = re.findall(r'@(\w+)', escaped_text)
    if not potential_mentions:
        return escaped_text

    # Check database for existing users in one query
    conn = get_db()
    placeholders = ','.join(['?'] * len(potential_mentions))
    query = f"SELECT username FROM users WHERE username IN ({placeholders})"
    rows = conn.execute(query, potential_mentions).fetchall()
    existing_users = [row['username'] for row in rows]

    # Replace only existing usernames with links
    processed_text = escaped_text
    for username in existing_users:
        # regex ensures we don't match @dan inside @danny
        pattern = r'@' + re.escape(username) + r'\b'
        link = f'<a href="/userprofile/{username}" class="mention-link">@{username}</a>'
        processed_text = re.sub(pattern, link, processed_text)
    
    return Markup(processed_text)

# Register it so you can use {{ content | mention | safe }} in Jinja

def connect_db():
    sql = sqlite3.connect(DATABASE)
    # turns the tuples default for sql rows into dictionaries. call these using table_name['col_name'] in code
    sql.row_factory = sqlite3.Row
    sql.execute("PRAGMA foreign_keys = ON")
    return sql

def get_db():
    if not hasattr(g, 'sqlite3_db'):
        g.sqlite3_db = connect_db()
    return g.sqlite3_db

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def get_event_chat(post_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM group_chats WHERE name=?",
        (f"Event Chat {post_id}",)
    ).fetchone()
    return dict(row) if row else None

# Create a new notification
def create_notification(user_id, actor_id, notif_type, message, link=None, reference_id=None):
    conn = get_db()
    conn.execute("""
        INSERT INTO notifications 
        (user_id, actor_id, type, reference_id, message, link)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, actor_id, notif_type, reference_id, message, link))
    conn.commit()

# Get all notifications for a user
def get_notifications(user_id, unread_only=False):
    conn = get_db()
    query = "SELECT * FROM notifications WHERE user_id=?"
    params = [user_id]
    if unread_only:
        query += " AND is_read=0"
    query += " ORDER BY created_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]

# Count unread notifications
def count_unread_notifications(user_id):
    conn = get_db()
    row = conn.execute("SELECT COUNT(*) AS cnt FROM notifications WHERE user_id=? AND is_read=0", (user_id,)).fetchone()
    return row['cnt']

# Mark a single notification as read
def mark_notification_read(notification_id):
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read=1 WHERE notification_id=?", (notification_id,))
    conn.commit()

# Mark all notifications for a user as read
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user_id,))
    conn.commit()


# --- E2EE Helpers ---
def get_user_public_key(user_id):
    conn = get_db()
    row = conn.execute("SELECT public_key FROM users WHERE user_id=?", (user_id,)).fetchone()
    return row['public_key'] if row else None

# --- Friend Helpers ---
def get_friend_requests(user_id):
    conn = get_db()
    requests = conn.execute("""
        SELECT f.friendship_id, u.username, p.display_name, f.created_at
        FROM friends f
        JOIN users u ON f.requester_id = u.user_id
        JOIN user_profiles p ON u.user_id = p.user_id
        WHERE f.addressee_id = ? AND f.status = 'pending'
        ORDER BY f.created_at DESC
    """, (user_id,)).fetchall()
    return [dict(r) for r in requests]

def get_friends(user_id):
    conn = get_db()
    friends = conn.execute("""
        SELECT u.user_id, u.username, COALESCE(p.display_name, u.username) as display_name
        FROM users u
        LEFT JOIN user_profiles p ON u.user_id = p.user_id
        WHERE u.user_id IN (
            SELECT requester_id FROM friends WHERE addressee_id = ? AND status='accepted'
            UNION
            SELECT addressee_id FROM friends WHERE requester_id = ? AND status='accepted'
        )
        ORDER BY display_name ASC
    """, (user_id, user_id)).fetchall()
    return [dict(f) for f in friends]

def is_friend(user_id, other_id):
    conn = get_db()
    exists = conn.execute("""
        SELECT 1 FROM friends 
        WHERE ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?))
        AND status='accepted'
    """, (user_id, other_id, other_id, user_id)).fetchone()
    return True if exists else False

def get_user_chats(user_id):
    conn = get_db()
    # Complex query to get last message for both direct messages and friends
    chats_query = conn.execute("""
        SELECT DISTINCT u.user_id, u.username, COALESCE(p.display_name, u.username) as display_name, u.public_key,
               (SELECT content 
                FROM messages 
                WHERE (sender_id = ? AND recipient_id = u.user_id)
                   OR (sender_id = u.user_id AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1
               ) AS last_message,
               (SELECT is_encrypted
                FROM messages 
                WHERE (sender_id = ? AND recipient_id = u.user_id)
                   OR (sender_id = u.user_id AND recipient_id = ?)
                ORDER BY created_at DESC LIMIT 1
               ) AS last_message_encrypted,
               (SELECT MAX(created_at) FROM messages m2
                WHERE (m2.sender_id = u.user_id AND m2.recipient_id = ?)
                   OR (m2.sender_id = ? AND m2.recipient_id = u.user_id)
               ) AS last_message_time
        FROM users u
        LEFT JOIN user_profiles p ON u.user_id = p.user_id

        WHERE u.user_id IN (
            -- STRICT MODE: Only Accepted Friends
            SELECT requester_id FROM friends WHERE addressee_id = ? AND status='accepted'
            UNION
            SELECT addressee_id FROM friends WHERE requester_id = ? AND status='accepted'
        )
        ORDER BY last_message_time DESC NULLS LAST, display_name ASC
    """, (user_id, user_id, user_id, user_id, user_id, user_id, user_id, user_id)).fetchall()

    chats = []
    for row in chats_query:
        chats.append({
            'user_id': row['user_id'],
            'username': row['username'],
            'display_name': row['display_name'],
            'public_key': row['public_key'],
            'last_message': row['last_message'] if row['last_message'] else "",
            'last_message_encrypted': row['last_message_encrypted'] if row['last_message_encrypted'] else 0,
            'last_message_time': row['last_message_time']
        })
    return chats

def get_current_user(conn):
    username = session.get("username")
    if not username:
        return None

    return conn.execute(
        "SELECT user_id, username FROM users WHERE username = ?",
        (username,)
    ).fetchone()

def fetch_post(conn, post_id):
    row = conn.execute("""
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

    if not row:
        return None

    post = dict(row)

    # Resolve display username once
    post["display_username"] = (
        post["organiser_username"]
        if post["post_type"] == "event" and post["organiser_username"]
        else post["creator_username"]
    )

    return post
def handle_event_registration(conn, post, user):
    if post["post_type"] != "event":
        return False

    if "register_event" not in request.form:
        return False

    exists = conn.execute("""
        SELECT 1 FROM event_registrations
        WHERE post_id = ? AND user_id = ?
    """, (post["post_id"], user["user_id"])).fetchone()

    if not exists:
        conn.execute("""
            INSERT INTO event_registrations (post_id, user_id)
            VALUES (?, ?)
        """, (post["post_id"], user["user_id"]))
        conn.commit()

    return True

def notify_post_owner(post, actor):
    post_owner_id = (
        post["organiser_id"]
        if post["post_type"] == "event" and post["organiser_id"]
        else post["user_id"]
    )

    if post_owner_id == actor["user_id"]:
        return

    create_notification(
        user_id=post_owner_id,
        actor_id=actor["user_id"],
        notif_type="comment",
        message=f"{actor['username']} commented on your post",
        link=url_for("openpost", post_id=post["post_id"]),
        reference_id=post["post_id"]
    )


def handle_comment_submission(conn, post, user):
    content = request.form.get("content", "").strip()
    if not content:
        return False

    conn.execute(
        "INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)",
        (post["post_id"], user["user_id"], content)
    )
    conn.commit()

    notify_post_owner(post, user)

    return True

def check_event_registration(conn, post, user):
    if not user or post["post_type"] != "event":
        return False

    result = conn.execute("""
        SELECT 1 FROM event_registrations
        WHERE post_id = ? AND user_id = ?
    """, (post["post_id"], user["user_id"])).fetchone()

    return bool(result)
def fetch_comments(conn, post_id, current_user_id=None):
    return conn.execute("""
        SELECT 
            c.comment_id, 
            c.content, 
            c.created_at, 
            u.username,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.comment_id) as like_count,
            (SELECT COUNT(*) FROM comment_likes cl WHERE cl.comment_id = c.comment_id AND cl.user_id = ?) as user_has_liked
        FROM comments c
        JOIN users u ON c.user_id = u.user_id
        WHERE c.post_id = ?
        ORDER BY c.created_at DESC
    """, (current_user_id, post_id)).fetchall()

