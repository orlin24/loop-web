
import os
import time
import json
import random
import threading
import logging
import pickle
import platform
import uuid
import hashlib
from datetime import datetime, timedelta
from collections import deque
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import fcntl

# Google API imports
try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    import google_auth_httplib2
    import httplib2
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False
    logging.error("Google libraries not found")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LoopBotCore:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.is_running = False
        self.is_streaming = False
        self.logs = deque(maxlen=500)  # Otomatis buang log lama, lebih efisien dari list
        self.running_streams = []
        self.youtube_service = None
        self.credentials = None
        self.channel_name = "Unknown"
        self.channel_thumbnail = ""
        self.channel_subscribers = "0"
        self.channel_id = None  # Track active channel ID for per-user content
        self.last_api_call = 0
        self.api_call_delay = 2
        self.api_lock = threading.Lock()
        self.shutdown_event = threading.Event()

        # HTTP session dengan connection pooling
        self.http_session = requests.Session()
        retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=5, pool_maxsize=10)
        self.http_session.mount("http://", adapter)
        self.http_session.mount("https://", adapter)
        
        # Load content
        self.titles = []
        self.descriptions = []
        self.streamkeys = []
        self.thumbnails = []
        self.tags_list = []
        
        # Tracking
        self.used_titles = set()
        self.used_descriptions = set()
        self.used_thumbnails = set()
        self.used_combinations = set()
        
        # Settings (defaults)
        self.settings = {
            'duration_hours': '00',
            'duration_minutes': '05',
            'duration_seconds': '00',
            'delay_minutes': 1,
            'max_streams': 1,
            'max_duplicates': 1,
            'auto_rotate_title': True,
            'randomize_content': True,
            'avoid_duplicates': False,
            'randomize_content': True,
            'avoid_duplicates': False,
            'filter_low_viewers': False,
            'min_vod_views': 500  # Auto-private if views < this value after stop
        }

        # Content items (advanced mode - replaces separate txt files)
        self.content_items = []

        self.load_data()
        self.load_content()
        self.load_credentials()

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)  # deque otomatis buang yang lama
        logging.info(message)

    def load_data(self):
        try:
            titles_path = os.path.join(self.base_dir, 'titles.txt')
            if os.path.exists(titles_path):
                with open(titles_path, 'r', encoding='utf-8') as f:
                    self.titles = [line.strip() for line in f if line.strip()]
            
            desc_path = os.path.join(self.base_dir, 'descriptions.txt')
            if os.path.exists(desc_path):
                with open(desc_path, 'r', encoding='utf-8') as f:
                    self.descriptions = [line.strip() for line in f if line.strip()]
            
            keys_path = os.path.join(self.base_dir, 'keystream.txt')
            if os.path.exists(keys_path):
                with open(keys_path, 'r', encoding='utf-8') as f:
                    self.streamkeys = [line.strip() for line in f if line.strip()]

            thumbs_dir = os.path.join(self.base_dir, 'thumbnails')
            if os.path.exists(thumbs_dir):
                self.thumbnails = []
                for ext in ['.png', '.jpg', '.jpeg']:
                     self.thumbnails.extend([os.path.join(thumbs_dir, f) for f in os.listdir(thumbs_dir) if f.lower().endswith(ext)])

            self.log_message(f"Loaded: {len(self.titles)} titles, {len(self.descriptions)} descriptions, {len(self.streamkeys)} keys, {len(self.thumbnails)} thumbnails")
        except Exception as e:
            self.log_message(f"Error loading data: {str(e)}")

    def get_content_path(self):
        """Get content file path - per channel if logged in, otherwise global"""
        if self.channel_id:
            # Per-channel content file
            content_dir = os.path.join(self.base_dir, 'content')
            if not os.path.exists(content_dir):
                os.makedirs(content_dir)
            return os.path.join(content_dir, f'content_{self.channel_id}.json')
        else:
            # No channel logged in - return None to indicate no content should load
            return None

    def load_content(self):
        """Load content items from JSON file with file locking - per channel"""
        try:
            content_path = self.get_content_path()

            # If no channel is logged in, content is empty
            if content_path is None:
                self.content_items = []
                # Silent - don't log during startup
                return

            if os.path.exists(content_path):
                with open(content_path, 'r', encoding='utf-8') as f:
                    fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                    try:
                        self.content_items = json.load(f)
                    finally:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                self.log_message(f"Loaded {len(self.content_items)} content items for channel {self.channel_id}")
            else:
                self.content_items = []
                self.log_message(f"No content file found for channel {self.channel_id} - starting fresh")
        except Exception as e:
            self.log_message(f"Error loading content: {str(e)}")
            self.content_items = []

    def save_content(self):
        """Save content items to JSON file with file locking (atomic write) - per channel"""
        try:
            content_path = self.get_content_path()

            # If no channel is logged in, cannot save
            if content_path is None:
                self.log_message("Cannot save content - no channel logged in")
                return

            temp_path = content_path + '.tmp'
            with open(temp_path, 'w', encoding='utf-8') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(self.content_items, f, indent=2, ensure_ascii=False)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            os.replace(temp_path, content_path)  # Atomic rename
            self.log_message(f"Saved {len(self.content_items)} content items for channel {self.channel_id}")
        except Exception as e:
            self.log_message(f"Error saving content: {str(e)}")

    def get_token_path(self):
        return os.path.join(self.base_dir, 'token.pickle')

    def get_client_secrets_path(self):
        return os.path.join(self.base_dir, 'client_secrets.json')

    def load_credentials(self):
        try:
            token_path = self.get_token_path()
            if os.path.exists(token_path):
                with open(token_path, 'rb') as token:
                    self.credentials = pickle.load(token)
                
                if self.credentials and self.credentials.valid:
                    self.create_service()
                    self.log_message("Credentials loaded and valid")
                elif self.credentials and self.credentials.expired and self.credentials.refresh_token:
                    self.credentials.refresh(Request())
                    with open(token_path, 'wb') as token:
                        pickle.dump(self.credentials, token)
                    self.create_service()
                    self.log_message("Credentials refreshed")
        except Exception as e:
            self.log_message(f"Error loading credentials: {str(e)}")

    def create_service(self):
        if self.credentials:
             try:
                # Disable SSL check if needed
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                # Manual http obj construction with auth
                http = httplib2.Http(disable_ssl_certificate_validation=True)
                http_auth = google_auth_httplib2.AuthorizedHttp(self.credentials, http=http)

                with self.api_lock:
                    self.youtube_service = build('youtube', 'v3', http=http_auth)

                    # Get channel info
                    request = self.youtube_service.channels().list(part="snippet,statistics", mine=True)
                    response = request.execute()

                if response.get('items'):
                    channel = response['items'][0]
                    old_channel_id = self.channel_id
                    self.channel_id = channel['id']  # Set channel ID
                    self.channel_name = channel['snippet']['title']
                    self.channel_thumbnail = channel['snippet']['thumbnails']['default']['url']
                    self.channel_subscribers = channel['statistics']['subscriberCount']

                    # Reload content for this channel if channel changed
                    if old_channel_id != self.channel_id:
                        self.load_content()
                        self.log_message(f"Switched to channel: {self.channel_name} ({self.channel_id})")
                else:
                    self.channel_id = None
                    self.channel_thumbnail = ""
                    self.channel_subscribers = "N/A"
                    self.content_items = []  # Clear content when no channel
             except Exception as e:
                 self.log_message(f"Service creation failed: {e}")

    def start_loop(self):
        if self.is_running:
            return

        if not self.youtube_service:
            self.log_message("Cannot start: YouTube not authenticated")
            return

        self.is_running = True
        self.is_streaming = True
        threading.Thread(target=self._automation_loop, daemon=True).start()
        threading.Thread(target=self._stats_monitor_loop, daemon=True).start()
        self.log_message("LoopBot automation started")

    def stop_loop(self):
        self.is_running = False
        self.is_streaming = False
        self.shutdown_event.set()
        self.log_message("LoopBot automation stopping...")

    def _stats_monitor_loop(self):
        """Background thread to update viewers count for all running streams"""
        while self.is_running and not self.shutdown_event.is_set():
            try:
                for stream in list(self.running_streams):
                    if not self.is_running or self.shutdown_event.is_set():
                        break
                    broadcast_id = stream.get('broadcast_id')
                    current_status = stream.get('status', '').lower()
                    # Only update stats for live streams
                    if broadcast_id and current_status == 'live':
                        try:
                            stats = self.get_live_broadcast_stats(broadcast_id)
                            stream['actual_viewers'] = stats.get('viewers', 0)
                            self.log_message(f"Stats: {broadcast_id[:8]}... viewers={stats.get('viewers', 0)}")
                        except Exception as e:
                            self.log_message(f"Stats error for {broadcast_id[:8]}: {e}")
                        # Delay between each stream to avoid rate limiting
                        if self.shutdown_event.wait(2):
                            break

                # Update every 60 seconds, bisa interrupted
                if self.shutdown_event.wait(60):
                    break
            except Exception as e:
                self.log_message(f"Stats monitor error: {e}")
                if self.shutdown_event.wait(60):
                    break

    def get_live_broadcast_stats(self, broadcast_id):
        """Get live broadcast statistics (viewers) from YouTube API"""
        try:
            if not self.youtube_service or not broadcast_id:
                return {"viewers": 0, "status": "unknown"}

            # Single API call - get viewers from videos.list
            with self.api_lock:
                video_response = self.youtube_service.videos().list(
                    part="liveStreamingDetails",
                    id=broadcast_id
                ).execute()

            viewers = 0
            if video_response.get("items"):
                live_details = video_response["items"][0].get("liveStreamingDetails", {})
                concurrent = live_details.get("concurrentViewers")
                if concurrent is not None:
                    viewers = int(concurrent)

            return {"viewers": viewers, "status": "live"}

        except Exception as e:
            # Don't log every error to reduce noise
            return {"viewers": 0, "status": "unknown"}

    def stop_single_stream(self, stream_id):
        """Stop a single stream by its ID"""
        try:
            stream_to_stop = None
            for stream in self.running_streams:
                if stream.get('id') == stream_id or stream.get('broadcast_id') == stream_id:
                    stream_to_stop = stream
                    break

            if not stream_to_stop:
                return False

            broadcast_id = stream_to_stop.get('broadcast_id')

            # Try to stop YouTube broadcast
            if broadcast_id and self.youtube_service:
                try:
                    with self.api_lock:
                        self.youtube_service.liveBroadcasts().transition(
                            part="status",
                            id=broadcast_id,
                            broadcastStatus="complete"
                        ).execute()
                    self.log_message(f"Broadcast {broadcast_id} stopped via API")
                except Exception as e:
                    self.log_message(f"Could not stop broadcast via API: {e}")

            # Remove from running streams
            self.running_streams = [s for s in self.running_streams if s.get('id') != stream_id]
            self.log_message(f"Stream {stream_id} removed from running list")
            return True

        except Exception as e:
            self.log_message(f"Error stopping stream {stream_id}: {e}")
            return False

    def stop_all_streams(self):
        """Stop all running streams"""
        count = len(self.running_streams)

        for stream in self.running_streams[:]:  # Copy list to avoid modification during iteration
            stream_id = stream.get('id')
            broadcast_id = stream.get('broadcast_id')

            if broadcast_id and self.youtube_service:
                try:
                    with self.api_lock:
                        self.youtube_service.liveBroadcasts().transition(
                            part="status",
                            id=broadcast_id,
                            broadcastStatus="complete"
                        ).execute()
                    self.log_message(f"Broadcast {broadcast_id} stopped")
                except Exception as e:
                    self.log_message(f"Could not stop broadcast {broadcast_id}: {e}")

        self.running_streams.clear()
        self.log_message(f"All {count} streams stopped")
        return count

    def _automation_loop(self):
        stream_counter = 0
        while self.is_running:
            try:
                # Auto-cleanup expired streams
                self._cleanup_expired_streams()

                available_keys = len(self.streamkeys) if self.streamkeys else 1
                max_duplicates = int(self.settings.get('max_duplicates', 1))
                max_streams = int(self.settings.get('max_streams', 1))
                max_concurrent = min(max_streams, available_keys * max_duplicates)

                if len(self.running_streams) >= max_concurrent:
                     time.sleep(5)
                     continue

                title, description, streamkey, thumbnail, tags = self.get_next_content()

                if not title:
                    # Check if it's because all keys are busy vs no content
                    available_content = [item for item in self.content_items if not item.get('used', False)]
                    if available_content:
                        # Content exists but keys are busy, wait and retry
                        self.log_message("Waiting for stream key to become available...")
                        time.sleep(10)
                        continue
                    else:
                        self.log_message("No more content available")
                        break

                stream_counter += 1

                # Calculate duration from settings
                duration_hours = int(self.settings.get('duration_hours', 0))
                duration_minutes = int(self.settings.get('duration_minutes', 5))
                duration_seconds_setting = int(self.settings.get('duration_seconds', 0))
                total_duration = (duration_hours * 3600) + (duration_minutes * 60) + duration_seconds_setting
                if total_duration <= 0:
                    total_duration = 300  # Default 5 minutes

                # Create broadcast
                self.log_message(f"Creating broadcast {stream_counter}: {title[:30]}")
                broadcast_id, bound_key = self.create_and_start_broadcast(title, description, streamkey, thumbnail, tags)

                if broadcast_id:
                    stream_id = f"stream_{stream_counter}_{int(time.time())}"
                    self.running_streams.append({
                        'id': stream_id,
                        'broadcast_id': broadcast_id,
                        'title': title,
                        'stream_key': bound_key,
                        'start_time': time.time(),
                        'duration_seconds': total_duration,
                        'status': 'live',
                        'actual_viewers': 0
                    })

                    self.log_message(f"Stream {stream_id} started, duration: {total_duration//60}m {total_duration%60}s")

                    delay = int(self.settings.get('delay_minutes', 3)) * 60
                    self.log_message(f"Waiting {delay} seconds before next creation...")

                    # Wait with check
                    for _ in range(delay):
                        if not self.is_running: break
                        time.sleep(1)
                else:
                    self.log_message("Failed to create broadcast, waiting 10s")
                    time.sleep(10)

            except Exception as e:
                self.log_message(f"Error in loop: {str(e)}")
                time.sleep(10)

    def _cleanup_expired_streams(self):
        """Remove streams that have exceeded their duration"""
        current_time = time.time()
        expired_streams = []

        for stream in self.running_streams:
            start_time = stream.get('start_time', current_time)
            duration = stream.get('duration_seconds', 300)
            elapsed = current_time - start_time

            if elapsed >= duration:
                expired_streams.append(stream)

        for stream in expired_streams:
            stream_id = stream.get('id')
            broadcast_id = stream.get('broadcast_id')
            title = stream.get('title', 'Unknown')
            duration = stream.get('duration_seconds', 300)

            # Try to stop YouTube broadcast
            if broadcast_id and self.youtube_service:
                try:
                    with self.api_lock:
                        self.youtube_service.liveBroadcasts().transition(
                            part="status",
                            id=broadcast_id,
                            broadcastStatus="complete"
                        ).execute()
                    self.log_message(f"Auto-stopped expired broadcast {broadcast_id}")
                except Exception as e:
                    self.log_message(f"Could not auto-stop broadcast {broadcast_id}: {e}")

            # Check Views & Auto-Private Logic
            view_count = 0
            privacy_status = "Public (Default)"
            
            if broadcast_id and self.youtube_service:
                try:
                    with self.api_lock:
                         # Get video stats
                        vid_req = self.youtube_service.videos().list(
                            part="statistics,status",
                            id=broadcast_id
                        ).execute()
                    
                    if vid_req.get('items'):
                        stats = vid_req['items'][0]['statistics']
                        view_count = int(stats.get('viewCount', 0))
                        
                        min_views = int(self.settings.get('min_vod_views', 0))
                        
                        if min_views > 0:
                            if view_count < min_views:
                                self.log_message(f"Views {view_count} < {min_views}. Setting to PRIVATE.")
                                with self.api_lock:
                                    self.youtube_service.videos().update(
                                        part="status",
                                        body={
                                            "id": broadcast_id,
                                            "status": {
                                                "privacyStatus": "private"
                                            }
                                        }
                                    ).execute()
                                privacy_status = "🔒 <b>PRIVATE</b> (Low Views)"
                            else:
                                privacy_status = "🌍 <b>PUBLIC</b> (Target Reached)"
                                
                except Exception as e:
                    self.log_message(f"Error checking views/privacy: {e}")

            # Send Telegram notification for stream end
            msg = (
                f"<b>🏁 Stream Auto-Stopped!</b>\n\n"
                f"📺 <b>Title:</b> {title}\n"
                f"⏰ <b>Duration:</b> {duration//60}m {duration%60}s\n"
                f"👁 <b>Views:</b> {view_count}\n"
                f"🛡 <b>Privacy:</b> {privacy_status}\n"
                f"🆔 <b>Stream ID:</b> {stream_id}\n"
                f"🔗 <b>Broadcast:</b> https://youtu.be/{broadcast_id}"
            )
            self.send_telegram_notification(msg)

            self.running_streams.remove(stream)
            self.log_message(f"Stream {stream_id} expired and removed")

    def process_spintax(self, text):
        pattern = r'\{([^}]+)\}'
        def replace(match):
            return random.choice(match.group(1).split('|'))
        return re.sub(pattern, replace, text)

    def get_active_stream_key_count(self, streamkey):
        """Count how many times a stream key is currently active in running_streams"""
        if not streamkey:
            return 0
        count = 0
        for stream in self.running_streams:
            if stream.get('stream_key') == streamkey:
                # Only count if stream is still active (not completed/error)
                status = stream.get('status', '')
                if status not in ['complete', 'error', 'timeout']:
                    count += 1
        return count

    def is_stream_key_available(self, streamkey):
        """Check if a stream key can be used based on max_duplicates setting"""
        max_duplicates = int(self.settings.get('max_duplicates', 1))
        current_count = self.get_active_stream_key_count(streamkey)
        return current_count < max_duplicates

    def get_next_content(self):
        # Use content_items if available (advanced mode)
        if self.content_items:
            # Filter available (not used) items
            available = [item for item in self.content_items if not item.get('used', False)]

            if not available:
                if self.settings.get('avoid_duplicates', True):
                    return None, None, None, None, None

                # Reset all if avoid_duplicates is off (loop back to start)
                self.log_message("All content used, resetting for next cycle")
                for item in self.content_items:
                    item['used'] = False
                available = self.content_items
                self.save_content()

            # Filter by stream key availability (respect max_duplicates)
            available_with_key = [
                item for item in available
                if self.is_stream_key_available(item.get('keystream', ''))
            ]

            if not available_with_key:
                # All stream keys are at max capacity
                self.log_message("All stream keys at max duplicates capacity, waiting...")
                return None, None, None, None, None

            if self.settings.get('randomize_content', True):
                item = random.choice(available_with_key)
            else:
                item = available_with_key[0]

            # Mark as used
            item['used'] = True

            # Find the actual item in the main list and update it
            # (Note: 'item' is a reference to the dict in content_items list, so updating it updates the main list)
            # Just to be safe/explicit if 'available' was a copy (it's shallow list copy above, but dicts inside are refs)

            self.save_content()

            title = item.get('title', '')
            description = self.process_spintax(item.get('desc', ''))
            streamkey = item.get('keystream', '')
            thumbnail = item.get('thumbnail', '')
            tags = item.get('tags', '')

            # Auto-Rotate Titles Logic (Advanced Mode)
            if self.settings.get('auto_rotate_title', True):
                # Basic rotation: Add unique suffix (Time or Random) to avoid duplicate content error
                suffix = f" | {int(time.time())}" 
                # Or more advanced: Shuffle words if user wants?
                # For now, let's append a random emoji or code to ensure uniqueness
                emojis = ["🔴", "🔥", "⚡", "✨", "📺", "🎥", "🎬", "🛑", "▶️", "✅"]
                title = f"{random.choice(emojis)} {title} {random.randint(100,999)}"

            self.log_message(f"Selected content with stream key: {streamkey[:15]}... (active: {self.get_active_stream_key_count(streamkey)})")

            return title, description, streamkey, thumbnail, tags

        # Fallback to legacy txt-based content
        if not self.titles:
            return None, None, None, None, None

        # For legacy mode, also check stream key availability
        available_keys = [key for key in self.streamkeys if self.is_stream_key_available(key)]
        if not available_keys:
            self.log_message("All stream keys at max duplicates capacity, waiting...")
            return None, None, None, None, None

        title = random.choice(self.titles)
        
        # Auto-Rotate Titles Logic (Legacy Mode)
        if self.settings.get('auto_rotate_title', True):
             emojis = ["🔴", "🔥", "⚡", "✨", "📺", "🎥", "🎬", "🛑", "▶️", "✅"]
             title = f"{random.choice(emojis)} {title} {random.randint(100,999)}"

        description = self.process_spintax(random.choice(self.descriptions)) if self.descriptions else ""
        streamkey = random.choice(available_keys) if available_keys else ""
        thumbnail = random.choice(self.thumbnails) if self.thumbnails else None
        tags = ""

        return title, description, streamkey, thumbnail, tags

    def create_and_start_broadcast(self, title, description, streamkey, thumbnail, tags):
        if not self.youtube_service: return None, None

        try:
            # Rate limiting
            current_time = time.time()
            time_since_last = current_time - self.last_api_call
            if time_since_last < self.api_call_delay:
                wait_time = self.api_call_delay - time_since_last
                self.log_message(f"Rate limiting: waiting {wait_time:.1f}s")
                time.sleep(wait_time)
            self.last_api_call = time.time()

            # 1. Find stream ID for key
            stream_id = self.find_stream_for_key(streamkey)
            if not stream_id:
                self.log_message(f"No stream ID found for key {streamkey}")
                return None, None

            self.log_message(f"Found stream ID: {stream_id} for key {streamkey[:15]}...")

            # 2. Create Broadcast
            broadcast_body = {
                "snippet": {
                    "title": title,
                    "description": description[:5000],
                    "scheduledStartTime": datetime.utcnow().isoformat() + "Z"
                },
                "status": {
                    "privacyStatus": "public"
                }
            }

            # Add tags if provided
            if tags:
                tags_list = [tag.strip() for tag in tags.split(',') if tag.strip()][:10]
                if tags_list:
                    broadcast_body["snippet"]["tags"] = tags_list
                    self.log_message(f"Adding {len(tags_list)} tags")

                    self.log_message(f"Adding {len(tags_list)} tags")

            with self.api_lock:
                broadcast = self.youtube_service.liveBroadcasts().insert(
                    part="snippet,status",
                    body=broadcast_body
                ).execute()
            broadcast_id = broadcast['id']
            self.log_message(f"Broadcast created: {broadcast_id}")

            # 3. Bind stream to broadcast
            try:
                with self.api_lock:
                    self.youtube_service.liveBroadcasts().bind(
                        part="id,contentDetails",
                        id=broadcast_id,
                        streamId=stream_id
                    ).execute()
                self.log_message(f"Broadcast bound to stream")
            except Exception as bind_error:
                error_msg = str(bind_error).lower()
                if "duplicate" in error_msg or "already" in error_msg:
                    self.log_message(f"Stream already bound (continuing): {streamkey[:15]}...")
                else:
                    self.log_message(f"Bind failed: {bind_error}")
                    # Delete the broadcast since bind failed
                    try:
                        with self.api_lock:
                            self.youtube_service.liveBroadcasts().delete(id=broadcast_id).execute()
                    except:
                        pass
                    return None, None

            # 4. Upload Thumbnail (convert URL to local path if needed)
            thumbnail_path = self.resolve_thumbnail_path(thumbnail)
            if thumbnail_path and os.path.exists(thumbnail_path):
                # Upload async to not block
                threading.Thread(
                    target=self.upload_thumbnail_async,
                    args=(broadcast_id, thumbnail_path),
                    daemon=True
                ).start()

            # 5. Transition to LIVE (Async with monitoring)
            threading.Thread(target=self.transition_to_live, args=(broadcast_id,), daemon=True).start()

            self.log_message(f"Broadcast ready: rtmp://a.rtmp.youtube.com/live2/{streamkey}")
            return broadcast_id, streamkey

        except Exception as e:
            self.log_message(f"Broadcast creation error: {e}")
            return None, None

    def resolve_thumbnail_path(self, thumbnail):
        """Convert thumbnail URL or path to actual file path"""
        if not thumbnail:
            return None

        # If it's already a valid file path
        if os.path.exists(thumbnail):
            return thumbnail

        # If it's a web URL like /loopbot/thumbnails/filename.jpg
        if thumbnail.startswith('/loopbot/thumbnails/'):
            filename = thumbnail.replace('/loopbot/thumbnails/', '')
            local_path = os.path.join(self.base_dir, 'thumbnails', filename)
            if os.path.exists(local_path):
                return local_path

        # Try to find in thumbnails directory by filename
        if '/' in thumbnail:
            filename = thumbnail.split('/')[-1]
        else:
            filename = thumbnail

        thumbs_dir = os.path.join(self.base_dir, 'thumbnails')
        if os.path.exists(thumbs_dir):
            potential_path = os.path.join(thumbs_dir, filename)
            if os.path.exists(potential_path):
                return potential_path

        return None

    def upload_thumbnail_async(self, broadcast_id, thumbnail_path):
        """Upload thumbnail asynchronously"""
        try:
            time.sleep(5)  # Wait for broadcast stabilization
            
            with self.api_lock:
                self.youtube_service.thumbnails().set(
                    videoId=broadcast_id,
                    media_body=MediaFileUpload(thumbnail_path)
                ).execute()
            self.log_message(f"Thumbnail uploaded for {broadcast_id}")
        except Exception as e:
            if "uploadRateLimitExceeded" in str(e):
                 self.log_message(f"Thumbnail upload SKIPPED (Rate Limit Exceeded)")
            else:
                 self.log_message(f"Thumbnail upload failed: {e}")

    def send_telegram_notification(self, message):
        """Send notification to Telegram"""
        try:
            # Try multiple paths for apibot.json
            possible_paths = [
                os.path.join(os.path.dirname(self.base_dir), 'uploads', 'apibot.json'),
                os.path.join(self.base_dir, '..', 'uploads', 'apibot.json'),
                os.path.join(os.getcwd(), 'uploads', 'apibot.json'),
                os.path.join(self.base_dir, 'telegram.json'),  # Alternative name
            ]

            settings = None
            for apibot_path in possible_paths:
                if os.path.exists(apibot_path):
                    with open(apibot_path, 'r') as f:
                        settings = json.load(f)
                        break

            if not settings:
                return  # No config found, silently skip

            bot_token = settings.get('botToken') or settings.get('bot_token')
            chat_id = settings.get('chatId') or settings.get('chat_id')

            # Check if enabled (optional field)
            enabled = settings.get('enabled', True)
            if not enabled:
                return

            if bot_token and chat_id:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = {
                    "chat_id": chat_id,
                    "text": message,
                    "parse_mode": "HTML"
                }
                response = self.http_session.post(url, json=payload, timeout=15)
                if response.status_code == 200:
                    self.log_message("Telegram notification sent")
                else:
                    self.log_message(f"Telegram failed: {response.status_code}")

        except Exception as e:
            self.log_message(f"Telegram error: {e}")

    def update_stream_status(self, broadcast_id, new_status):
        """Update status of a stream in running_streams list"""
        for stream in self.running_streams:
            if stream.get('broadcast_id') == broadcast_id:
                stream['status'] = new_status
                return True
        return False

    def transition_to_live(self, broadcast_id):
        """Monitor broadcast and transition to live (Synced with Desktop App Logic)"""
        try:
            self.log_message(f"Monitor: Waiting for stream data (FFmpeg) to connect for {broadcast_id}...")
            self.update_stream_status(broadcast_id, 'starting')

            # Timeout logic from run.py (approx 15 mins)
            timeout_minutes = 15
            start_time = time.time()
            timeout_seconds = timeout_minutes * 60

            while time.time() - start_time < timeout_seconds:
                try:
                    if not self.youtube_service:
                        return

                    # 1. Check current status
                    with self.api_lock:
                        request = self.youtube_service.liveBroadcasts().list(
                            part="status,contentDetails,snippet",
                            id=broadcast_id
                        )
                        response = request.execute()

                    if not response.get('items'):
                        self.log_message(f"Monitor: Broadcast {broadcast_id} not found.")
                        self.update_stream_status(broadcast_id, 'error')
                        return

                    broadcast = response['items'][0]
                    lifecycle_status = broadcast['status']['lifeCycleStatus']
                    snippet = broadcast['snippet']

                    # Update status in running_streams
                    self.update_stream_status(broadcast_id, lifecycle_status)

                    if lifecycle_status == 'complete':
                        self.log_message(f"Monitor: Broadcast {broadcast_id} is complete.")
                        return

                    if lifecycle_status == 'live':
                        self.log_message(f"SUCCESS: Broadcast {broadcast_id} is already LIVE!")
                        # Send Success Notification
                        msg = (
                            f"<b>🎉 Stream Started!</b>\n"
                            f"📺 <b>Title:</b> {snippet.get('title', 'Unknown')}\n"
                            f"🆔 <b>Stream ID:</b> {broadcast_id}\n"
                            f"🔗 <b>Link:</b> https://youtu.be/{broadcast_id}\n"
                            f"🤖 <b>Status:</b> LIVE"
                        )
                        self.send_telegram_notification(msg)
                        return

                    # Logic from run.py: wait_for_encoder_and_go_live
                    if lifecycle_status == 'testing':
                        self.log_message("Monitor: FFmpeg connected! Stream testing... (Stabilizing 30s)")
                        self.update_stream_status(broadcast_id, 'testing')
                        time.sleep(30)  # Stabilization

                        try:
                            with self.api_lock:
                                self.youtube_service.liveBroadcasts().transition(
                                    part="status",
                                    id=broadcast_id,
                                    broadcastStatus="live"
                                ).execute()

                            self.log_message(f"SUCCESS: Broadcast {broadcast_id} is now LIVE!")
                            self.update_stream_status(broadcast_id, 'live')

                            # Double check status after short delay to confirm
                            time.sleep(5)
                            with self.api_lock:
                                check_req = self.youtube_service.liveBroadcasts().list(part="status", id=broadcast_id).execute()
                            final_status = check_req['items'][0]['status']['lifeCycleStatus']

                            if final_status == 'live':
                                msg = (
                                    f"<b>🎉 Stream Started!</b>\n"
                                    f"📺 <b>Title:</b> {snippet.get('title', 'Unknown')}\n"
                                    f"🆔 <b>Stream ID:</b> {broadcast_id}\n"
                                    f"🔗 <b>Link:</b> https://youtu.be/{broadcast_id}\n"
                                    f"🤖 <b>Status:</b> LIVE"
                                )
                                self.send_telegram_notification(msg)
                            else:
                                self.log_message(f"Warning: Tried to go live but status is {final_status}")
                                self.update_stream_status(broadcast_id, final_status)

                            return

                        except Exception as e:
                            if "invalidTransition" in str(e):
                                self.log_message("Monitor: Still stabilizing...")
                            else:
                                self.log_message(f"Monitor error in testing: {e}")

                    # If ready, try to start testing
                    elif lifecycle_status == 'ready':
                        self.update_stream_status(broadcast_id, 'ready')
                        # We can try to force 'testing' state if stream data is present but not auto-detected
                        # But usually YouTube auto-detects. run.py just checks for 'testing' or 'live'.
                        # However, sometimes we need to kick it to 'testing'.
                        try:
                            with self.api_lock:
                                self.youtube_service.liveBroadcasts().transition(
                                    part="status",
                                    id=broadcast_id,
                                    broadcastStatus="testing"
                                ).execute()
                            self.update_stream_status(broadcast_id, 'testing')
                        except Exception:
                            pass  # Likely 'invalidTransition' because no data yet.

                        self.log_message(f"Monitor: Waiting for Video Data (RTMP)... ({int(time.time() - start_time)}s)")

                    time.sleep(15)

                except Exception as e:
                    self.log_message(f"Monitor error: {e}")
                    time.sleep(15)

            self.log_message(f"Monitor: Timeout after {timeout_minutes} minutes for {broadcast_id}")
            self.update_stream_status(broadcast_id, 'timeout')

        except Exception as e:
            self.log_message(f"Monitor fatal error: {e}")
            self.update_stream_status(broadcast_id, 'error')

    def find_stream_for_key(self, key):
        # Try to find a stream resource that matches this key.
        # This is tricky because the API list doesn't show the full key usually, or we need to match by something else.
        # run.py has complex logic for this.
        # We will try a simple list and check if we can reuse 'any' active stream or create one?
        # Actually, if the key is provided, the user usually pasted the key string. 
        # But `bind` requires `streamId`.
        # We need `liveStreams.list` to find the `id` corresponding to the key string.
        # BUT `liveStreams.list` returns `cdn.ingestionInfo.streamName` which IS the stream key.
        try:
            with self.api_lock:
                request = self.youtube_service.liveStreams().list(
                    part="id,cdn,status",
                    mine=True
                )
                response = request.execute()
            for item in response.get('items', []):
                # We check streamName (the key)
                if item['cdn']['ingestionInfo']['streamName'] == key:
                    return item['id']
            
            # If not found, maybe create it?
            # run.py seems to reuse.
            return None
        except Exception as e:
            self.log_message(f"Error searching streams: {e}")
            return None

loop_bot = LoopBotCore(os.path.join(os.getcwd(), 'LoopBot'))
