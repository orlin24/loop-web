
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from loopbot_core import loop_bot
from werkzeug.utils import secure_filename
import os
import google_auth_oauthlib.flow
from google.oauth2.credentials import Credentials
import json
import uuid

# Thumbnail upload config
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_thumbnails_dir():
    thumbs_dir = os.path.join(loop_bot.base_dir, 'thumbnails')
    if not os.path.exists(thumbs_dir):
        os.makedirs(thumbs_dir)
    return thumbs_dir

loopbot_bp = Blueprint('loopbot', __name__, template_folder='templates')

@loopbot_bp.route('/loopbot')
def index():
    # Pass status and logs
    return render_template('loopbot.html', 
                           is_running=loop_bot.is_running,
                           logs=loop_bot.logs[-20:] if loop_bot.logs else [],
                           channel_name=loop_bot.channel_name,
                           channel_thumbnail=loop_bot.channel_thumbnail,
                           channel_subscribers=loop_bot.channel_subscribers,
                           logged_in=loop_bot.youtube_service is not None)

@loopbot_bp.route('/loopbot/start', methods=['POST'])
def start_loop():
    loop_bot.start_loop()
    return jsonify({'success': True, 'message': 'Loop started'})

@loopbot_bp.route('/loopbot/stop', methods=['POST'])
def stop_loop():
    loop_bot.stop_loop()
    return jsonify({'success': True, 'message': 'Loop stopped'})

@loopbot_bp.route('/loopbot/logs')
def get_logs():
    return jsonify({'logs': loop_bot.logs[-50:]})

@loopbot_bp.route('/loopbot/status')
def get_status():
    return jsonify({
        'is_running': loop_bot.is_running,
        'channel_name': loop_bot.channel_name,
        'channel_thumbnail': loop_bot.channel_thumbnail,
        'channel_subscribers': loop_bot.channel_subscribers,
        'broadcast_count': len(loop_bot.running_streams),
        'authenticated': loop_bot.youtube_service is not None
    })

@loopbot_bp.route('/loopbot/auth')
def auth():
    client_secrets = loop_bot.get_client_secrets_path()
    if not os.path.exists(client_secrets):
        return "client_secrets.json not found in LoopBot folder", 404
        
    scopes = ['https://www.googleapis.com/auth/youtube', 'https://www.googleapis.com/auth/youtube.force-ssl']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        client_secrets, scopes=scopes)
    
    # Force exact match with Google Cloud Console
    # This solves issues where Nginx might pass 'www' or 'http' unexpectedly
    flow.redirect_uri = "https://loopbotiq.com/loopbot/oauth2callback"
    
    print(f"DEBUG: Using Hardcoded Redirect URI: {flow.redirect_uri}") # Debugging
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    
    session['state'] = state
    return redirect(authorization_url)

@loopbot_bp.route('/loopbot/oauth2callback')
def oauth2callback():
    state = session.get('state')
    if not state:
        return "Session state missing (cookie lost?). Try clearing browser cookies.", 400
    
    client_secrets = loop_bot.get_client_secrets_path()
    scopes = ['https://www.googleapis.com/auth/youtube', 'https://www.googleapis.com/auth/youtube.force-ssl']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        client_secrets, scopes=scopes, state=state)
        
    # MUST match exactly what was sent in auth()
    flow.redirect_uri = "https://loopbotiq.com/loopbot/oauth2callback"
    print(f"DEBUG: Callback Redirect URI: {flow.redirect_uri}") # Debugging
    
    authorization_response = request.url
    # Fix for http vs https in callback URL if Nginx didn't rewrite it perfectly
    if authorization_response.startswith('http:'):
        authorization_response = authorization_response.replace('http:', 'https:', 1)

    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    
    try:
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        
        # 1. Build temp service to get channel info
        from googleapiclient.discovery import build
        service = build('youtube', 'v3', credentials=credentials)
        
        # 2. Get Channel Info
        response = service.channels().list(part="snippet,statistics", mine=True).execute()
        if not response.get('items'):
            return "No YouTube channel found for this account", 400
            
        channel = response['items'][0]
        c_id = channel['id']
        c_title = channel['snippet']['title']
        c_thumb = channel['snippet']['thumbnails']['default']['url']
        c_subs = channel['statistics'].get('subscriberCount', 0)
        c_views = channel['statistics'].get('viewCount', 0)
        c_videos = channel['statistics'].get('videoCount', 0)
        
        # 3. Save specific token file
        token_dir = os.path.join(loop_bot.base_dir, 'tokens')
        if not os.path.exists(token_dir):
            os.makedirs(token_dir)
            
        token_filename = f'token_{c_id}.pickle'
        token_path = os.path.join(token_dir, token_filename)
        
        import pickle
        with open(token_path, 'wb') as token_file:
            pickle.dump(credentials, token_file)
            
        # 4. Update channels.json
        channels_file = os.path.join(loop_bot.base_dir, 'channels.json')
        channels = []
        if os.path.exists(channels_file):
            with open(channels_file, 'r') as f:
                try: 
                    channels = json.load(f)
                except: 
                    channels = []
        
        # Remove existing if present (update)
        channels = [c for c in channels if c['id'] != c_id]
        
        # Add new
        channels.append({
            'id': c_id,
            'title': c_title,
            'thumbnail': c_thumb,
            'subscriberCount': c_subs,
            'viewCount': c_views,
            'videoCount': c_videos,
            'token_file': token_filename,
            'last_updated': str(uuid.uuid4()) # rudimentary timestamp/version
        })
        
        with open(channels_file, 'w') as f:
            json.dump(channels, f, indent=2)
            
        # 5. Set as Active (Copy to token.pickle)
        import shutil
        active_token_path = loop_bot.get_token_path()
        shutil.copy(token_path, active_token_path)
        
        # 6. Reload Bot
        loop_bot.load_credentials()
        
        return redirect('/loopbot/channels')
    except Exception as e:
        return f"Auth failed: {e}", 500

@loopbot_bp.route('/loopbot/channels')
def channels_page():
    return render_template('channels.html')

@loopbot_bp.route('/loopbot/channels/list')
def list_channels():
    try:
        channels_file = os.path.join(loop_bot.base_dir, 'channels.json')
        channels = []
        if os.path.exists(channels_file):
            with open(channels_file, 'r') as f:
                channels = json.load(f)
        
        # Determine active channel
        active_id = None
        if loop_bot.youtube_service:
            # We can try to match channel ID from loop_bot info
            # Or assume the one we just logged in. 
            # loop_bot doesn't store channel ID explicitly in public var, let's fetch it or guess?
            # Actually loop_bot.create_service() fetches channel info. 
            # We can rely on loop_bot.channel_name comparison or add channel_id to LoopBotCore.
            # Ideally LoopBotCore should expose Channel ID.
            # But for now let's just use Name? No, Name is not unique.
            # We can fetch mine=True again? Expensive.
            pass
            
        # Better: Check token.pickle hash against stored tokens?
        # Or just trust the user click.
        # Let's verify active by looking at loop_bot
        
        for c in channels:
            # Simple check: if bot is running and channel name matches?
            # Or we can store 'active_channel_id' in a separate file/config?
            # Let's perform a check if loop_bot.channel_name matches c['title'] 
            # (imperfect but good enough for UI highlighting)
            c['active'] = (c['title'] == loop_bot.channel_name)
            
        return jsonify({'success': True, 'channels': channels})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@loopbot_bp.route('/loopbot/channels/delete/<id>', methods=['POST'])
def delete_channel(id):
    try:
        channels_file = os.path.join(loop_bot.base_dir, 'channels.json')
        if not os.path.exists(channels_file):
            return jsonify({'success': False, 'message': 'No channels file'})
            
        with open(channels_file, 'r') as f:
            channels = json.load(f)
            
        target = next((c for c in channels if c['id'] == id), None)
        if not target:
             return jsonify({'success': False, 'message': 'Channel not found'})
             
        # Check if this was the active channel
        # We compare the content of the token files to be sure
        is_active_channel = False
        active_token_path = loop_bot.get_token_path()
        
        if os.path.exists(active_token_path) and os.path.exists(token_path):
            try:
                with open(active_token_path, 'rb') as f1, open(token_path, 'rb') as f2:
                    if f1.read() == f2.read():
                        is_active_channel = True
            except:
                pass # If read error, fallback to name check
                
        if not is_active_channel and loop_bot.channel_name == target['title']:
            is_active_channel = True

        # Remove token file
        if os.path.exists(token_path):
            os.remove(token_path)
            
        # Update JSON
        channels = [c for c in channels if c['id'] != id]
        with open(channels_file, 'w') as f:
            json.dump(channels, f, indent=2)

        # If it was active OR no channels left, clear session
        if is_active_channel or len(channels) == 0:
            if os.path.exists(active_token_path):
                os.remove(active_token_path)
            
            # Reset LoopBot state
            loop_bot.youtube_service = None
            loop_bot.channel_name = None
            loop_bot.channel_thumbnail = None
            loop_bot.channel_subscribers = "N/A"
            loop_bot.start_loop() # This effectively stops/resets if service is None? 
            # Actually stop_loop() is better to ensure threads stop
            loop_bot.stop_loop()
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@loopbot_bp.route('/loopbot/channels/switch/<id>', methods=['POST'])
def switch_channel(id):
    try:
        channels_file = os.path.join(loop_bot.base_dir, 'channels.json')
        with open(channels_file, 'r') as f:
            channels = json.load(f)
            
        target = next((c for c in channels if c['id'] == id), None)
        if not target:
             return jsonify({'success': False, 'message': 'Channel not found'})
             
        token_path = os.path.join(loop_bot.base_dir, 'tokens', target['token_file'])
        if not os.path.exists(token_path):
            return jsonify({'success': False, 'message': 'Token file missing for this channel'})
            
        # Copy to active
        import shutil
        active_token_path = loop_bot.get_token_path()
        shutil.copy(token_path, active_token_path)
        
        # Reload LoopBot
        loop_bot.load_credentials()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@loopbot_bp.route('/loopbot/settings', methods=['GET'])
def get_settings():
    """Get current settings"""
    try:
        return jsonify({'success': True, 'settings': loop_bot.settings})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/settings', methods=['POST'])
def update_settings():
    try:
        data = request.json
        loop_bot.settings.update(data)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

# Content Management Endpoints
@loopbot_bp.route('/loopbot/content', methods=['GET'])
def get_content():
    """Get all content items"""
    try:
        return jsonify({'success': True, 'content': loop_bot.content_items})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/content', methods=['POST'])
def add_content():
    """Add new content item"""
    try:
        data = request.json
        if not data.get('title') or not data.get('keystream'):
            return jsonify({'success': False, 'message': 'Title and Stream Key are required'}), 400

        content_item = {
            'title': data.get('title', ''),
            'desc': data.get('desc', ''),
            'keystream': data.get('keystream', ''),
            'thumbnail': data.get('thumbnail', ''),
            'tags': data.get('tags', ''),
            'used': False
        }
        loop_bot.content_items.append(content_item)
        loop_bot.save_content()
        return jsonify({'success': True, 'message': 'Content added'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/content/bulk', methods=['POST'])
def add_content_bulk():
    """Add multiple content items at once"""
    try:
        data = request.json
        items = data.get('items', [])

        if not items:
            return jsonify({'success': False, 'message': 'No items provided'}), 400

        added_count = 0
        for item in items:
            if item.get('title') and item.get('keystream'):
                content_item = {
                    'title': item.get('title', ''),
                    'desc': item.get('desc', ''),
                    'keystream': item.get('keystream', ''),
                    'thumbnail': item.get('thumbnail', ''),
                    'tags': item.get('tags', ''),
                    'used': False
                }
                loop_bot.content_items.append(content_item)
                added_count += 1

        if added_count > 0:
            loop_bot.save_content()

        return jsonify({
            'success': True,
            'message': f'Added {added_count} content items',
            'count': added_count
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/content/import', methods=['POST'])
def import_content():
    """Import content from JSON (replace or append)"""
    try:
        mode = request.args.get('mode', 'append')  # 'replace' or 'append'
        data = request.json
        items = data.get('items', [])

        if not items:
            return jsonify({'success': False, 'message': 'No items provided'}), 400

        # If replace mode, clear existing content
        if mode == 'replace':
            loop_bot.content_items.clear()

        added_count = 0
        for item in items:
            if item.get('title') and item.get('keystream'):
                content_item = {
                    'title': item.get('title', ''),
                    'desc': item.get('desc', ''),
                    'keystream': item.get('keystream', ''),
                    'thumbnail': item.get('thumbnail', ''),
                    'tags': item.get('tags', ''),
                    'used': False
                }
                loop_bot.content_items.append(content_item)
                added_count += 1

        if added_count > 0:
            loop_bot.save_content()

        action = 'Replaced with' if mode == 'replace' else 'Added'
        return jsonify({
            'success': True,
            'message': f'{action} {added_count} content items',
            'count': added_count
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/content/<int:index>', methods=['PUT'])
def update_content(index):
    """Update existing content item"""
    try:
        if index < 0 or index >= len(loop_bot.content_items):
            return jsonify({'success': False, 'message': 'Invalid index'}), 404

        data = request.json
        if not data.get('title') or not data.get('keystream'):
            return jsonify({'success': False, 'message': 'Title and Stream Key are required'}), 400

        loop_bot.content_items[index].update({
            'title': data.get('title', ''),
            'desc': data.get('desc', ''),
            'keystream': data.get('keystream', ''),
            'thumbnail': data.get('thumbnail', ''),
            'tags': data.get('tags', '')
        })
        loop_bot.save_content()
        return jsonify({'success': True, 'message': 'Content updated'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/content/<int:index>', methods=['DELETE'])
def delete_content(index):
    """Delete content item"""
    try:
        if index < 0 or index >= len(loop_bot.content_items):
            return jsonify({'success': False, 'message': 'Invalid index'}), 404

        loop_bot.content_items.pop(index)
        loop_bot.save_content()
        return jsonify({'success': True, 'message': 'Content deleted'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/reset-used-content', methods=['POST'])
def reset_used_content():
    """Reset used status for all content"""
    try:
        for item in loop_bot.content_items:
            item['used'] = False
        loop_bot.save_content()
        return jsonify({'success': True, 'message': 'Used content reset'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/check-stream-keys', methods=['POST'])
def check_stream_keys():
    """Check validity of stream keys"""
    try:
        valid = 0
        invalid = 0
        total = len(loop_bot.content_items)

        for item in loop_bot.content_items:
            key = item.get('keystream', '')
            # Basic validation: check if key matches expected format
            if key and len(key) >= 10 and '-' in key:
                valid += 1
            else:
                invalid += 1

        return jsonify({
            'success': True,
            'valid': valid,
            'invalid': invalid,
            'total': total
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/clear-logs', methods=['POST'])
def clear_logs():
    """Clear all logs"""
    try:
        loop_bot.logs.clear()
        return jsonify({'success': True, 'message': 'Logs cleared'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

# Running Streams Management Endpoints
@loopbot_bp.route('/loopbot/running-streams', methods=['GET'])
def get_running_streams():
    """Get list of currently running streams with progress info"""
    try:
        import time
        streams_data = []

        # Optionally refresh stats on request (if refresh=true query param)
        refresh = request.args.get('refresh', 'false').lower() == 'true'

        for stream in loop_bot.running_streams:
            broadcast_id = stream.get('broadcast_id')
            current_status = stream.get('status', '').lower()

            # Fetch fresh stats if requested and stream is active
            if refresh and broadcast_id and current_status not in ['complete', 'error', 'timeout']:
                stats = loop_bot.get_live_broadcast_stats(broadcast_id)
                stream['actual_viewers'] = stats.get('viewers', 0)
                if stats.get('status'):
                    stream['status'] = stats['status']

            # Calculate progress
            start_time = stream.get('start_time', time.time())
            duration_seconds = stream.get('duration_seconds', 300)  # Default 5 min
            elapsed = time.time() - start_time
            remaining = max(0, duration_seconds - elapsed)
            progress = min(100, (elapsed / duration_seconds) * 100) if duration_seconds > 0 else 0

            streams_data.append({
                'id': stream.get('id', ''),
                'broadcast_id': stream.get('broadcast_id', ''),
                'stream_key': stream.get('stream_key', ''),
                'title': stream.get('title', 'Unknown'),
                'status': stream.get('status', 'unknown'),
                'viewers': stream.get('actual_viewers', 0),
                'start_time': start_time,
                'duration_seconds': duration_seconds,
                'elapsed': int(elapsed),
                'remaining': f"{int(remaining // 60)}m {int(remaining % 60)}s",
                'progress': round(progress, 1)
            })

        return jsonify({
            'success': True,
            'streams': streams_data,
            'count': len(streams_data)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e), 'streams': []}), 400

@loopbot_bp.route('/loopbot/stop-stream/<stream_id>', methods=['POST'])
def stop_single_stream(stream_id):
    """Stop a single running stream"""
    try:
        result = loop_bot.stop_single_stream(stream_id)
        if result:
            return jsonify({'success': True, 'message': f'Stream {stream_id} stopped'})
        else:
            return jsonify({'success': False, 'message': 'Stream not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/stop-all-streams', methods=['POST'])
def stop_all_streams():
    """Stop all running streams"""
    try:
        count = loop_bot.stop_all_streams()
        return jsonify({'success': True, 'message': f'Stopped {count} streams', 'count': count})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

# Thumbnail Management Endpoints
@loopbot_bp.route('/loopbot/thumbnails', methods=['GET'])
def get_thumbnails():
    """Get list of all uploaded thumbnails"""
    try:
        thumbs_dir = get_thumbnails_dir()
        thumbnails = []

        for filename in os.listdir(thumbs_dir):
            if allowed_file(filename):
                filepath = os.path.join(thumbs_dir, filename)
                thumbnails.append({
                    'filename': filename,
                    'url': f'/loopbot/thumbnails/{filename}',
                    'path': filepath,
                    'size': os.path.getsize(filepath)
                })

        # Sort by filename
        thumbnails.sort(key=lambda x: x['filename'])

        return jsonify({'success': True, 'thumbnails': thumbnails})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/thumbnails/<filename>')
def serve_thumbnail(filename):
    """Serve thumbnail image"""
    thumbs_dir = get_thumbnails_dir()
    return send_from_directory(thumbs_dir, filename)

@loopbot_bp.route('/loopbot/thumbnails/upload', methods=['POST'])
def upload_thumbnails():
    """Upload one or multiple thumbnails"""
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'message': 'No files provided'}), 400

        files = request.files.getlist('files')
        thumbs_dir = get_thumbnails_dir()

        uploaded = []
        errors = []

        for file in files:
            if file and file.filename:
                if allowed_file(file.filename):
                    # Generate unique filename to avoid conflicts
                    ext = file.filename.rsplit('.', 1)[1].lower()
                    original_name = secure_filename(file.filename.rsplit('.', 1)[0])
                    # Keep original name but add uuid if exists
                    filename = f"{original_name}.{ext}"
                    filepath = os.path.join(thumbs_dir, filename)

                    # If file exists, add uuid
                    if os.path.exists(filepath):
                        filename = f"{original_name}_{uuid.uuid4().hex[:8]}.{ext}"
                        filepath = os.path.join(thumbs_dir, filename)

                    file.save(filepath)
                    uploaded.append({
                        'filename': filename,
                        'url': f'/loopbot/thumbnails/{filename}',
                        'path': filepath
                    })
                else:
                    errors.append(f"{file.filename}: Invalid file type")

        return jsonify({
            'success': True,
            'uploaded': uploaded,
            'errors': errors,
            'count': len(uploaded)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400

@loopbot_bp.route('/loopbot/thumbnails/<filename>', methods=['DELETE'])
def delete_thumbnail(filename):
    """Delete a thumbnail"""
    try:
        thumbs_dir = get_thumbnails_dir()
        filepath = os.path.join(thumbs_dir, secure_filename(filename))

        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'success': True, 'message': 'Thumbnail deleted'})
        else:
            return jsonify({'success': False, 'message': 'File not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400
