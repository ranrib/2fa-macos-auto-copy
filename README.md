# 2fa-macos-monitor
Monitors MacOS Messages app for incoming messages with 2FA codes


```bash
touch /Applications/2fa_monitor.py
touch ~/Library/LaunchAgents/com.2fa.monitor.plist
launchctl load ~/Library/LaunchAgents/com.2fa.monitor.plist
```

Grant full disk access:
1. Open System Settings
2. Go to Privacy & Security → Full Disk Access
3. Click the lock and authenticate
4. Add your Terminal/Python app:
5. Toggle it ON
6. IMPORTANT: Completely quit and restart your Terminal
7. Run this script again
