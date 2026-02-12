"""
💬 REAL-TIME CHAT SYSTEM
========================

Features:
✅ All users can send messages to all other users
✅ Real-time message broadcasting
✅ Message history persists
✅ Shows username + timestamp
✅ Thread-safe with locking
✅ Database persistence for report generation
"""

from datetime import datetime
from collections import deque
import threading
import json
import os
import sqlite3

# Global chat storage (in-memory for demo, can be saved to disk)
chat_messages = deque(maxlen=500)  # Keep last 500 messages
chat_lock = threading.Lock()

# File to persist chat history
CHAT_HISTORY_FILE = '../data/chat_history.json'


def init_chat_database():
    """Initialize chat messages table in database"""
    try:
        # Ensure data directory exists
        os.makedirs('../data', exist_ok=True)
        
        conn = sqlite3.connect('../data/dashboard.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                role TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✓ Chat messages table initialized")
    except Exception as e:
        print(f"Error initializing chat messages table: {e}")


def init_chat_system():
    """Initialize chat system and load history"""
    global chat_messages
    
    # Initialize database table first
    init_chat_database()
    
    # Try to load existing chat history
    if os.path.exists(CHAT_HISTORY_FILE):
        try:
            with open(CHAT_HISTORY_FILE, 'r') as f:
                history = json.load(f)
                with chat_lock:
                    chat_messages = deque(history, maxlen=500)
                print(f"✓ Chat system initialized with {len(chat_messages)} messages")
        except Exception as e:
            print(f"⚠️  Could not load chat history: {e}")
            chat_messages = deque(maxlen=500)
    else:
        print("✓ Chat system initialized (no previous history)")
    
    return True


def send_message(username, message, role='user'):
    """
    Send a message to the chat
    
    Args:
        username: Username of sender
        message: Message text
        role: Role of sender (user/admin)
    
    Returns:
        Message object that was added
    """
    with chat_lock:
        msg_obj = {
            'id': len(chat_messages) + 1,
            'username': username,
            'message': message.strip(),
            'role': role,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'time_short': datetime.now().strftime('%H:%M')
        }
        
        chat_messages.append(msg_obj)
        
        # Save to disk periodically (every message for safety)
        _save_chat_history()
        
        # Also save to database
        try:
            conn = sqlite3.connect('../data/dashboard.db')
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO chat_messages (username, message, role, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (username, message.strip(), role, msg_obj['timestamp']))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving chat message to database: {e}")
        
        print(f"[CHAT] {username}: {message[:50]}...")
        
        return msg_obj


def get_messages(limit=100):
    """
    Get recent chat messages
    
    Args:
        limit: Maximum number of messages to return
    
    Returns:
        List of message objects
    """
    with chat_lock:
        return list(chat_messages)[-limit:]


def get_messages_since(last_id=0):
    """
    Get messages since a specific message ID (for real-time updates)
    
    Args:
        last_id: Get messages with ID > last_id
    
    Returns:
        List of new message objects
    """
    with chat_lock:
        new_messages = [msg for msg in chat_messages if msg['id'] > last_id]
        return new_messages


def clear_chat_history():
    """Clear all chat messages (admin only)"""
    global chat_messages
    with chat_lock:
        chat_messages.clear()
        _save_chat_history()
        
        # Also clear database
        try:
            conn = sqlite3.connect('../data/dashboard.db')
            cursor = conn.cursor()
            cursor.execute('DELETE FROM chat_messages')
            conn.commit()
            conn.close()
            print("[CHAT] History cleared from memory and database")
        except Exception as e:
            print(f"Error clearing chat database: {e}")
        
        return True


def _save_chat_history():
    """Save chat history to disk"""
    try:
        # Ensure data directory exists
        os.makedirs(os.path.dirname(CHAT_HISTORY_FILE), exist_ok=True)
        
        with open(CHAT_HISTORY_FILE, 'w') as f:
            json.dump(list(chat_messages), f, indent=2)
    except Exception as e:
        print(f"⚠️  Could not save chat history: {e}")


# Initialize on import
print("💬 Chat system module loaded")
init_chat_system()