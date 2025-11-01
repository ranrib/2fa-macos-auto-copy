#!/usr/bin/env python3
"""
2FA Code Auto-Copy Monitor (Python Version - Improved)
Monitors macOS Messages database for 2FA codes with proper text extraction
"""

import sqlite3
import re
import time
import subprocess
import os
from pathlib import Path
from datetime import datetime

class TwoFactorMonitor:
    def __init__(self):
        # Messages database path
        self.db_path = Path.home() / "Library" / "Messages" / "chat.db"
        
        # Regular expression patterns for 2FA codes
        self.patterns = {
            '6-digit': re.compile(r'\b\d{6}\b'),
            '4-digit': re.compile(r'\b\d{4}\b'),
            '6-char': re.compile(r'\b[A-Z0-9]{6}\b'),
            '4-char': re.compile(r'\b[A-Z0-9]{4}\b'),
        }
        
        # Track processed messages and codes
        self.last_message_id = 0
        self.processed_codes = []
        self.max_processed_codes = 10
        
        # Check interval in seconds
        self.check_interval = 2
        
        print("=== 2FA Monitor Starting ===")
        print(f"Current time: {datetime.now()}")
        print(f"Database path: {self.db_path}")
        
        # Check permissions
        self.check_permissions()
        
    def check_permissions(self):
        """Check if we have access to the Messages database"""
        print("\n--- Permission Check ---")
        
        # Check if database exists
        if not self.db_path.exists():
            print("❌ ERROR: Messages database not found!")
            print(f"   Expected at: {self.db_path}")
            print("   Make sure Messages app has been opened at least once.")
            return False
        else:
            print(f"✅ Database file exists: {self.db_path}")
        
        # Check if we can read the file
        if not os.access(self.db_path, os.R_OK):
            print("❌ ERROR: No read permission for Messages database!")
            print("\n🔧 SOLUTION:")
            print("   1. Open System Settings")
            print("   2. Go to Privacy & Security → Full Disk Access")
            print("   3. Click the lock and authenticate")
            print("   4. Add your Terminal app:")
            print("      - For Terminal: /Applications/Utilities/Terminal.app")
            print("      - For iTerm2: /Applications/iTerm.app")
            print("   5. Toggle it ON")
            print("   6. IMPORTANT: Completely quit and restart your Terminal")
            print("   7. Run this script again")
            return False
        else:
            print("✅ Read permission granted")
        
        # Try to open the database
        try:
            conn = sqlite3.connect(f'file:{self.db_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM message")
            count = cursor.fetchone()[0]
            conn.close()
            print(f"✅ Successfully connected to database")
            print(f"✅ Found {count} total messages")
            print("--- Permission Check Complete ---\n")
            return True
        except sqlite3.Error as e:
            print(f"❌ ERROR connecting to database: {e}")
            print("\n🔧 POSSIBLE SOLUTIONS:")
            print("   1. Make sure Messages app is NOT open (try quitting it)")
            print("   2. Grant Full Disk Access to Terminal (see instructions above)")
            return False
    
    def show_notification(self, title, message, sound=True):
        """Show macOS notification"""
        try:
            sound_part = ' sound name "Glass"' if sound else ''
            cmd = [
                'osascript', '-e',
                f'display notification "{message}" with title "{title}"{sound_part}'
            ]
            subprocess.run(cmd, check=False, capture_output=True)
            print(f"Notification: {title} - {message}")
        except Exception as e:
            print(f"ERROR showing notification: {e}")
    
    def copy_to_clipboard(self, text):
        """Copy text to macOS clipboard"""
        try:
            process = subprocess.Popen(
                ['pbcopy'],
                stdin=subprocess.PIPE,
                close_fds=True
            )
            process.communicate(text.encode('utf-8'))
            print(f"Copied to clipboard: {text}")
            return True
        except Exception as e:
            print(f"ERROR copying to clipboard: {e}")
            return False
    
    def extract_text_from_attributed_body(self, attributed_body):
        """Extract readable text from the binary attributedBody field"""
        try:
            if not attributed_body:
                return None
            
            # The attributedBody contains encoded NSAttributedString
            # Look for readable text patterns
            
            # Decode as UTF-8, ignoring errors
            try:
                text = attributed_body.decode('utf-8', errors='ignore')
            except:
                try:
                    text = attributed_body.decode('latin-1', errors='ignore')
                except:
                    return None
            
            # Extract readable portions (ASCII + Hebrew + common unicode)
            # Hebrew range: \u0590-\u05FF
            # Remove control characters and keep readable text
            readable_chars = []
            for char in text:
                # Keep: letters, numbers, spaces, punctuation, Hebrew
                if (char.isprintable() or char.isspace()) and ord(char) >= 32:
                    readable_chars.append(char)
            
            readable_text = ''.join(readable_chars)
            
            # Clean up - remove excessive whitespace and non-printable sequences
            readable_text = re.sub(r'\s+', ' ', readable_text).strip()
            
            # Return text if it's substantial enough
            if len(readable_text) > 3:
                return readable_text
            
            return None
            
        except Exception as e:
            print(f"Error extracting text: {e}")
            return None
    
    def extract_code(self, text):
        """Extract 2FA code from text using regex patterns"""
        # Try each pattern in order of priority
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(text)
            if match:
                code = match.group(0)
                print(f"Found {pattern_name} code: {code}")
                return code
        
        return None
    
    def process_message(self, message_text, message_id, chat_id):
        """Process a message and look for 2FA codes"""
        print(f"\n>>> Processing message ID {message_id}")
        print(f"Text preview: {message_text[:100]}...")
        
        code = self.extract_code(message_text)
        
        if code:
            print(f"Code detected: {code}")
            
            # Check if we've already processed this code
            if code not in self.processed_codes:
                print("Code is NEW - copying to clipboard")
                
                # Copy to clipboard
                if self.copy_to_clipboard(code):
                    # Show notification
                    self.show_notification(
                        "2FA Code Detected ✓",
                        f"Code copied to clipboard: {code}"
                    )
                    
                    # Add to processed list
                    self.processed_codes.append(code)
                    print(f"Code added to processed list. Total processed: {len(self.processed_codes)}")
                    
                    # Keep only last N codes
                    if len(self.processed_codes) > self.max_processed_codes:
                        self.processed_codes = self.processed_codes[-self.max_processed_codes:]
                        print(f"Trimmed processed list to {self.max_processed_codes} items")
                    
                    return code
            else:
                print("Code already processed - skipping (duplicate)")
        else:
            print("No code found in message")
        
        return None
    
    def get_recent_messages(self):
        """Query Messages database for recent messages"""
        try:
            # Connect to Messages database (read-only)
            conn = sqlite3.connect(f'file:{self.db_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            
            # Query for recent messages
            # We'll get both text and attributedBody to extract content
            query = """
                SELECT 
                    message.ROWID,
                    message.text,
                    message.attributedBody,
                    message.date,
                    chat.ROWID as chat_id,
                    chat.chat_identifier
                FROM message
                JOIN chat_message_join ON message.ROWID = chat_message_join.message_id
                JOIN chat ON chat_message_join.chat_id = chat.ROWID
                WHERE message.ROWID > ? 
                    AND message.is_from_me = 0
                ORDER BY message.date DESC
                LIMIT 20
            """
            
            cursor.execute(query, (self.last_message_id,))
            rows = cursor.fetchall()
            
            conn.close()
            
            # Process rows to extract text
            messages = []
            for row in rows:
                message_id, text, attributed_body, date, chat_id, chat_identifier = row
                
                # Use text field if available, otherwise extract from attributedBody
                message_text = text
                
                if not message_text and attributed_body:
                    message_text = self.extract_text_from_attributed_body(attributed_body)
                
                # Only include if we got some text
                if message_text and len(message_text.strip()) > 0:
                    messages.append((message_id, message_text, date, chat_id, chat_identifier))
            
            return messages
            
        except sqlite3.Error as e:
            print(f"ERROR querying database: {e}")
            return []
        except Exception as e:
            print(f"ERROR in get_recent_messages: {e}")
            return []
    
    def check_for_new_messages(self):
        """Check for new messages and process them"""
        print("--- Checking for new messages ---")
        
        messages = self.get_recent_messages()
        
        if not messages:
            print("No new messages found")
            return
        
        print(f"Found {len(messages)} message(s) to check")
        
        for message_id, text, date, chat_id, chat_identifier in messages:
            print(f"\nChecking message ID: {message_id} from {chat_identifier}")
            
            # Update last processed message ID
            if message_id > self.last_message_id:
                self.last_message_id = message_id
                
                # Process the message
                self.process_message(text, message_id, chat_id)
    
    def run(self):
        """Main monitoring loop"""
        # Check if database exists
        if not self.db_path.exists():
            print(f"ERROR: Messages database not found at {self.db_path}")
            print("Make sure Messages app is set up and you have Full Disk Access permission")
            return
        
        # Show startup notification
        self.show_notification(
            "2FA Monitor Active",
            "Monitoring for 2FA codes in Messages"
        )
        
        print(f"Monitoring Messages database every {self.check_interval} seconds...")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.check_for_new_messages()
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            print("\n=== 2FA Monitor Stopping ===")
            print(f"Total codes processed in session: {len(self.processed_codes)}")
            self.show_notification(
                "2FA Monitor",
                "2FA Code Monitor stopped",
                sound=False
            )


if __name__ == "__main__":
    print("=" * 60)
    print("2FA Code Auto-Copy Monitor")
    print("Python Version for macOS")
    print("=" * 60)
    print()
    
    monitor = TwoFactorMonitor()
    monitor.run()