"""
server.py — Run this on one machine on the network.

Security improvements:
  - bcrypt for password hashing (replaces plain sha256)
  - Session tokens issued on login — prevents identity spoofing
  - Rate limiting on LOGIN/REGISTER per IP — prevents brute-force attacks
  - Concurrent session enforcement — one session per user at a time
  - Input validation (username length, allowed characters, parameterized queries)
  - Cryptographically secure room codes (secrets module)
"""

import json
import random
import socket
import sqlite3
import threading
import secrets
import hashlib
import re
import time
import requests
import os
import bcrypt
from groq import Groq
import ssl
from dotenv import load_dotenv
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
API_KEY = os.getenv("TMDB_API_KEY")
if not API_KEY:
    raise RuntimeError("Missing TMDB_API_KEY in .env")
if not GROQ_API_KEY:
    raise RuntimeError("Missing GROQ_API_KEY in .env")

BASE_URL = "https://api.themoviedb.org/3"
HOST     = "0.0.0.0"
PORT     = 5555
DB_FILE  = "users.db"

USERNAME_MIN = 3
USERNAME_MAX = 32
PASSWORD_MIN = 6
PASSWORD_MAX = 128
USERNAME_RE  = re.compile(r'^[a-zA-Z0-9_\-]+$')

_rate_data: dict  = {}
_rate_lock        = threading.Lock()
RATE_WINDOW       = 60
RATE_MAX_ATTEMPTS = 10
RATE_LOCKOUT      = 120

_sessions:      dict = {}
_sessions_lock       = threading.Lock()
_user_session:  dict = {}

movie_count: dict = {}
watch_rooms: dict = {}
rooms_lock        = threading.Lock()

GENRE_NAMES = {
    28: "Action", 12: "Adventure", 16: "Animation", 35: "Comedy",
    80: "Crime", 99: "Documentary", 18: "Drama", 10751: "Family",
    14: "Fantasy", 36: "History", 27: "Horror", 10402: "Music",
    9648: "Mystery", 10749: "Romance", 878: "Sci-Fi",
    53: "Thriller", 10752: "War", 37: "Western"
}


# ─── Input validation ─────────────────────────────────

def validate_username(username: str) -> str | None:
    """
    Validates a username against length and character rules.
    Returns an error string if invalid, or None if the username is acceptable.
    Prevents SQL-injection-friendly characters and enforces a consistent format.
    """
    if not isinstance(username, str):
        return "Invalid username type"
    if len(username) < USERNAME_MIN:
        return f"Username must be at least {USERNAME_MIN} characters"
    if len(username) > USERNAME_MAX:
        return f"Username must be at most {USERNAME_MAX} characters"
    if not USERNAME_RE.match(username):
        return "Username may only contain letters, digits, _ and -"
    return None


def validate_password(password: str) -> str | None:
    """
    Validates a password against minimum and maximum length constraints.
    Returns an error string if invalid, or None if the password is acceptable.
    """
    if not isinstance(password, str):
        return "Invalid password type"
    if len(password) < PASSWORD_MIN:
        return f"Password must be at least {PASSWORD_MIN} characters"
    if len(password) > PASSWORD_MAX:
        return f"Password is too long"
    return None


# ─── Rate limiting ────────────────────────────────────

def _check_rate_limit(ip: str) -> bool:
    """
    Returns True if the IP address is allowed to make a login/register attempt.
    After RATE_MAX_ATTEMPTS failures within RATE_WINDOW seconds,
    the IP is locked out for RATE_LOCKOUT seconds.
    The failure counter resets automatically once the window expires.
    """
    now = time.time()
    with _rate_lock:
        entry = _rate_data.get(ip)
        if entry is None:
            _rate_data[ip] = {"count": 0, "locked_until": 0}
            return True
        if entry.get("locked_until", 0) > now:
            return False
        if now - entry.get("last", 0) > RATE_WINDOW:
            entry["count"] = 0
            entry["locked_until"] = 0
        return entry["count"] < RATE_MAX_ATTEMPTS


def _record_failure(ip: str):
    """
    Records a failed login or register attempt for the given IP.
    Once the failure count reaches RATE_MAX_ATTEMPTS, locks out the IP
    for RATE_LOCKOUT seconds.
    """
    now = time.time()
    with _rate_lock:
        entry = _rate_data.setdefault(ip, {"count": 0, "locked_until": 0})
        entry["count"] = entry.get("count", 0) + 1
        entry["last"]  = now
        if entry["count"] >= RATE_MAX_ATTEMPTS:
            entry["locked_until"] = now + RATE_LOCKOUT


def _record_success(ip: str):
    """
    Clears the failure history for an IP after a successful login.
    Resets the rate-limit counter so the user is not penalised for past failures.
    """
    with _rate_lock:
        _rate_data.pop(ip, None)


# ─── Session management ───────────────────────────────

def _create_session(username: str) -> str:
    """
    Issues a new 256-bit cryptographically secure session token for the user.
    If the user already has an active session from another device,
    that old token is invalidated first — enforcing one session per user at a time.
    Returns the new token string.
    """
    token = secrets.token_hex(32)
    with _sessions_lock:
        old_token = _user_session.get(username)
        if old_token:
            _sessions.pop(old_token, None)
        _sessions[token]        = username
        _user_session[username] = token
    return token


def _validate_session(token: str) -> str | None:
    """
    Validates a session token and returns the associated username if valid,
    or None if the token does not exist or has been invalidated.
    """
    with _sessions_lock:
        return _sessions.get(token)


def _destroy_session(token: str):
    """
    Removes a session token when the client disconnects.
    Also clears the username-to-token mapping so the user can log in again.
    """
    with _sessions_lock:
        username = _sessions.pop(token, None)
        if username:
            _user_session.pop(username, None)


# ─── Database ─────────────────────────────────────────

def init_db():
    """
    Creates all required database tables if they do not already exist:
      - users:            credentials and favourite movies
      - movies:           per-user movie library with status and rating
      - friends:          friendship records with pending/accepted status
      - shown_movies_log: tracks which movies have been shown to each user
    Also performs a migration: adds the favorite_movies column to existing databases
    that were created before this column was introduced.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS movies (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT NOT NULL,
            movie_id     INTEGER NOT NULL,
            title        TEXT,
            release_date TEXT,
            vote_average REAL,
            poster_path  TEXT,
            status       TEXT NOT NULL,
            rating       INTEGER DEFAULT NULL,
            genre_ids    TEXT DEFAULT '[]',
            UNIQUE(username, movie_id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS friends (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            friend   TEXT NOT NULL,
            status   TEXT NOT NULL DEFAULT 'pending',
            UNIQUE(username, friend)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS shown_movies_log (
            username TEXT    NOT NULL,
            movie_id INTEGER NOT NULL,
            PRIMARY KEY (username, movie_id)
        )
    """)
    existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "favorite_movies" not in existing_cols:
        conn.execute("ALTER TABLE users ADD COLUMN favorite_movies TEXT DEFAULT '[]'")
    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """
    Hashes a plain-text password using bcrypt with an automatically generated salt.
    bcrypt is intentionally slow, making it resistant to brute-force and rainbow-table attacks.
    The salt is embedded in the returned hash string, so no separate column is needed.
    Returns a UTF-8 string suitable for storage in the database.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """
    Compares a plain-text password against a stored bcrypt hash.
    Uses constant-time comparison internally, preventing timing attacks.
    Returns True if the password matches, False otherwise.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def register_user(username: str, password: str) -> dict:
    """
    Registers a new user: validates inputs, hashes the password, and inserts into the DB.
    Returns {"status": "error"} if the username is taken or input is invalid,
    {"status": "ok"} on success.
    """
    err = validate_username(username)
    if err:
        return {"status": "error", "message": err}
    err = validate_password(password)
    if err:
        return {"status": "error", "message": err}
    hashed = hash_password(password)
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed)
        )
        conn.commit()
        return {"status": "ok", "message": "Registration successful"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Username already exists"}
    finally:
        conn.close()


def login_user(username: str, password: str) -> dict:
    """
    Validates login credentials and issues a session token on success.
    Returns a generic error message on failure — intentionally does not reveal
    whether the username exists, to prevent user enumeration attacks.
    On success, creates a session via _create_session() and returns the token.
    """
    err = validate_username(username)
    if err:
        return {"status": "error", "message": "Wrong username or password"}
    err = validate_password(password)
    if err:
        return {"status": "error", "message": "Wrong username or password"}
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT password FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row and verify_password(password, row[0]):
        token = _create_session(username)
        return {"status": "ok", "message": f"Welcome, {username}!", "token": token}
    return {"status": "error", "message": "Wrong username or password"}


def save_movie(username: str, movie: dict, status: str, rating: int = None) -> dict:
    """
    Saves or updates a movie in the user's library.
    Supports three statuses: want_to_watch, already_watched, dont_want.
    Uses ON CONFLICT DO UPDATE so the same movie can change status without duplication.
    Validates both the status value and the rating range (1-10) before writing.
    """
    if status not in ("want_to_watch", "already_watched", "dont_want"):
        return {"status": "error", "message": "Invalid status"}
    if rating is not None:
        try:
            rating = int(rating)
            if not (1 <= rating <= 10):
                return {"status": "error", "message": "Rating must be 1-10"}
        except (ValueError, TypeError):
            return {"status": "error", "message": "Invalid rating"}
    conn = sqlite3.connect(DB_FILE)
    try:
        conn.execute("""
            INSERT INTO movies (username, movie_id, title, release_date, vote_average,
                                poster_path, status, rating, genre_ids)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username, movie_id) DO UPDATE SET
                status    = excluded.status,
                rating    = excluded.rating,
                genre_ids = excluded.genre_ids
        """, (
            username,
            int(movie.get("movie_id")),
            str(movie.get("title", ""))[:256],
            str(movie.get("release_date", ""))[:10],
            float(movie.get("vote_average", 0)),
            str(movie.get("poster_path", ""))[:512],
            status,
            rating,
            json.dumps(movie.get("genre_ids", [])),
        ))
        conn.commit()
        return {"status": "ok"}
    finally:
        conn.close()


def get_movies_by_status(username: str, status: str) -> list:
    """
    Returns all movies for a user filtered by the given status string.
    Validates the status value before querying to prevent arbitrary DB reads.
    """
    if status not in ("want_to_watch", "already_watched", "dont_want"):
        return []
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT movie_id, title, release_date, vote_average, poster_path, rating "
        "FROM movies WHERE username = ? AND status = ?",
        (username, status)
    ).fetchall()
    conn.close()
    return [{"movie_id": r[0], "title": r[1], "release_date": r[2],
             "vote_average": r[3], "poster_path": r[4], "rating": r[5]} for r in rows]


def get_all_user_movie_ids(username: str) -> set:
    """
    Returns a set of all movie IDs in the user's library (across all three lists).
    Used to filter out already-seen movies from the recommendation pool.
    """
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT movie_id FROM movies WHERE username = ?", (username,)
    ).fetchall()
    conn.close()
    return {r[0] for r in rows}


def add_friend(username: str, friend: str) -> dict:
    """
    Sends a friend request from username to friend.
    Validates that the target user exists, that the sender is not adding themselves,
    and that a request has not already been sent.
    """
    if username == friend:
        return {"status": "error", "message": "You can't add yourself"}
    err = validate_username(friend)
    if err:
        return {"status": "error", "message": "Invalid username"}
    conn = sqlite3.connect(DB_FILE)
    user_exists = conn.execute(
        "SELECT id FROM users WHERE username = ?", (friend,)
    ).fetchone()
    if not user_exists:
        conn.close()
        return {"status": "error", "message": "User not found"}
    try:
        conn.execute(
            "INSERT INTO friends (username, friend, status) VALUES (?, ?, 'pending')",
            (username, friend)
        )
        conn.commit()
        return {"status": "ok", "message": f"Friend request sent to {friend}!"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Request already sent"}
    finally:
        conn.close()


def get_friends(username: str) -> list:
    """Returns a list of usernames who are accepted friends of the given user."""
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT friend FROM friends WHERE username = ? AND status = 'accepted'",
        (username,)
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def get_pending_requests(username: str) -> list:
    """
    Returns a list of usernames who have sent pending friend requests to this user.
    Used by the client's 5-second polling loop to display incoming request popups.
    """
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT username FROM friends WHERE friend = ? AND status = 'pending'",
        (username,)
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def accept_friend(username: str, requester: str) -> dict:
    """
    Accepts a pending friend request.
    Updates the existing record to 'accepted' and inserts the reverse record
    so that the friendship is bidirectional in the database.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "UPDATE friends SET status = 'accepted' WHERE username = ? AND friend = ?",
        (requester, username)
    )
    try:
        conn.execute(
            "INSERT INTO friends (username, friend, status) VALUES (?, ?, 'accepted')",
            (username, requester)
        )
    except sqlite3.IntegrityError:
        conn.execute(
            "UPDATE friends SET status = 'accepted' WHERE username = ? AND friend = ?",
            (username, requester)
        )
    conn.commit()
    conn.close()
    return {"status": "ok"}


def decline_friend(username: str, requester: str) -> dict:
    """Declines a friend request by deleting the pending record from the database."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "DELETE FROM friends WHERE username = ? AND friend = ?",
        (requester, username)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


def calculate_compatibility(username: str, friend: str) -> dict:
    """
    Computes a cinematic compatibility score between two users using three layers:
      Layer 1 (70%): Rating similarity — average of 1 - |ratingA - ratingB| / 9
                     for movies both users have watched and rated.
      Layer 2 (20%): Want-to-watch overlap — how often both users agree on
                     movies they want (or disagree: one wants, the other skips).
      Layer 3 (10%): Shared dislikes — proportion of dont_want movies where
                     both users independently decided to skip.
    Returns the final weighted score as a percentage, plus per-layer breakdowns.
    """
    conn = sqlite3.connect(DB_FILE)

    def get_all_movies(user):
        rows = conn.execute(
            "SELECT movie_id, status, rating FROM movies WHERE username = ?", (user,)
        ).fetchall()
        return {r[0]: {"status": r[1], "rating": r[2]} for r in rows}

    user_movies   = get_all_movies(username)
    friend_movies = get_all_movies(friend)
    conn.close()
    shared = set(user_movies) & set(friend_movies)

    rating_scores = []
    for mid in shared:
        u, f = user_movies[mid], friend_movies[mid]
        if u["status"] == "already_watched" and f["status"] == "already_watched":
            ur, fr = u.get("rating"), f.get("rating")
            if ur and fr:
                rating_scores.append(1.0 - abs(ur - fr) / 9.0)
    layer1 = (sum(rating_scores) / len(rating_scores)) if rating_scores else 0.5

    want_scores = []
    for mid in shared:
        u_want = user_movies[mid]["status"] == "want_to_watch"
        f_want = friend_movies[mid]["status"] == "want_to_watch"
        u_dont = user_movies[mid]["status"] == "dont_want"
        f_dont = friend_movies[mid]["status"] == "dont_want"
        if u_want and f_want:
            want_scores.append(1.0)
        elif (u_want and f_dont) or (u_dont and f_want):
            want_scores.append(0.0)
    layer2 = (sum(want_scores) / len(want_scores)) if want_scores else 0.5

    dont_scores = []
    for mid in shared:
        u_dont = user_movies[mid]["status"] == "dont_want"
        f_dont = friend_movies[mid]["status"] == "dont_want"
        if u_dont or f_dont:
            dont_scores.append(1.0 if (u_dont and f_dont) else 0.0)
    layer3 = (sum(dont_scores) / len(dont_scores)) if dont_scores else 0.5

    final = (layer1 * 0.70) + (layer2 * 0.20) + (layer3 * 0.10)
    return {
        "status":      "ok",
        "final":       round(final * 100),
        "layer1":      round(layer1 * 100),
        "layer2":      round(layer2 * 100),
        "layer3":      round(layer3 * 100),
        "rated_count": len(rating_scores),
        "want_count":  len(want_scores),
        "dont_count":  len(dont_scores),
    }


# ─── Shown-movies persistence ─────────────────────────

def db_get_shown_ids(username: str) -> set:
    """
    Returns the set of all movie IDs that have ever been shown to this user.
    Persisted in the shown_movies_log table so the history survives server restarts.
    Used to filter the recommendation pool and prevent repeats.
    """
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT movie_id FROM shown_movies_log WHERE username = ?", (username,)
    ).fetchall()
    conn.close()
    return {r[0] for r in rows}


def db_mark_shown(username: str, movie_id: int):
    """
    Records that a movie has been shown to the user.
    Uses INSERT OR IGNORE so duplicate entries are silently skipped.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "INSERT OR IGNORE INTO shown_movies_log (username, movie_id) VALUES (?, ?)",
        (username, int(movie_id))
    )
    conn.commit()
    conn.close()


# ─── Recommendation engine ────────────────────────────

def get_user_taste_profile(username: str) -> dict:
    """
    Builds a structured taste profile from the user's complete movie history.
    Returns a dict with four keys:
      - top_rated:   list of (title, rating) for movies the user rated 8 or above
      - want_titles: up to 10 titles from the want-to-watch list
      - dont_titles: up to 10 titles from the dont-want list
      - fav_movies:  the 3 manually chosen all-time favourites from the profile page
    This profile is passed directly to the Groq prompt as context for personalisation.
    """
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT title, status, rating FROM movies WHERE username = ?", (username,)
    ).fetchall()
    fav_row = conn.execute(
        "SELECT favorite_movies FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    top_rated   = [(r[0], r[2]) for r in rows if r[1] == "already_watched" and r[2] and r[2] >= 8]
    want_titles = [r[0] for r in rows if r[1] == "want_to_watch"][:10]
    dont_titles = [r[0] for r in rows if r[1] == "dont_want"][:10]

    fav_movies = []
    if fav_row:
        try:
            fav_movies = [t for t in json.loads(fav_row[0] or "[]") if t.strip()]
        except Exception:
            fav_movies = []

    return {
        "top_rated":   top_rated,
        "want_titles": want_titles,
        "dont_titles": dont_titles,
        "fav_movies":  fav_movies,
    }


def get_friend_unseen_movies(username: str) -> list:
    """
    Finds movies that high-compatibility friends (60%+ match) rated 9 or 10,
    and that the current user has not yet seen.
    These are injected into the AI recommendation candidate pool as social signals.
    Returns a list of (friend_name, movie_id, title, rating) tuples.
    """
    friends   = get_friends(username)
    user_seen = get_all_user_movie_ids(username)
    results   = []
    for friend in friends:
        compat = calculate_compatibility(username, friend)
        if compat["final"] < 60:
            continue
        conn = sqlite3.connect(DB_FILE)
        rows = conn.execute(
            "SELECT movie_id, title, rating FROM movies WHERE username = ? AND rating >= 9",
            (friend,)
        ).fetchall()
        conn.close()
        for movie_id, title, rating in rows:
            if movie_id not in user_seen:
                results.append((friend, movie_id, title, rating))
    return results


def ai_pick_and_explain(username: str, candidates: list) -> tuple:
    """
    Asks Groq / LLaMA-3.3 to pick the best movie from a candidate list
    and write a one-sentence personalised reason for the recommendation.

    Process:
      1. Builds the user's taste profile (top_rated, fav_movies, want, dont).
      2. Adds unseen movies loved by high-compatibility friends.
      3. Shuffles the combined pool and samples up to 20 candidates.
      4. Sends the profile + candidates to the LLM with a structured prompt.
      5. Parses the PICK: / REASON: response format with a fuzzy fallback.
      6. On any error, returns a random candidate with a generic reason.

    Returns (movie_dict, reason_str).
    """
    profile   = get_user_taste_profile(username)
    user_seen = get_all_user_movie_ids(username)

    friend_unseen = get_friend_unseen_movies(username)
    unseen_candidates = [m for m in candidates if m["id"] not in user_seen]

    candidate_ids = {m["id"] for m in unseen_candidates}
    for friend_name, movie_id, title, rating in friend_unseen:
        if movie_id not in candidate_ids:
            try:
                r = requests.get(
                    f"{BASE_URL}/movie/{movie_id}",
                    params={"api_key": API_KEY, "language": "en-US"},
                    timeout=6
                )
                r.raise_for_status()
                data = r.json()
                unseen_candidates.append({
                    "id":           data.get("id"),
                    "title":        data.get("title", title),
                    "release_date": data.get("release_date", ""),
                    "vote_average": data.get("vote_average", 0),
                    "vote_count":   data.get("vote_count", 0),
                    "overview":     data.get("overview", ""),
                    "poster_path":  data.get("poster_path", ""),
                    "genre_ids":    [g["id"] for g in data.get("genres", [])],
                    "_from_friend": friend_name,
                })
                candidate_ids.add(movie_id)
            except Exception:
                pass

    if not unseen_candidates:
        return None, "Popular right now"

    shuffled = list(unseen_candidates)
    random.shuffle(shuffled)
    pool = shuffled[:20]

    top_rated_shuffled = list(profile["top_rated"])
    random.shuffle(top_rated_shuffled)
    top_str = ", ".join(f'"{t}" ({r}/10)' for t, r in top_rated_shuffled[:6]) or "none yet"
    fav_str = ", ".join(f'"{t}"' for t in profile["fav_movies"]) or "none yet"

    want_shuffled = list(profile["want_titles"])
    random.shuffle(want_shuffled)
    dont_shuffled = list(profile["dont_titles"])
    random.shuffle(dont_shuffled)

    want_str = ", ".join(f'"{t}"' for t in want_shuffled[:5]) or "none yet"
    dont_str = ", ".join(f'"{t}"' for t in dont_shuffled[:5]) or "none yet"

    candidates_str = "\n".join(
        f'{i+1}. "{m["title"]}" ({str(m.get("release_date",""))[:4]}) — '
        f'{m.get("overview","")[:200]}'
        for i, m in enumerate(pool)
    )

    prompt = f"""You are a movie recommendation engine. Your goal is to pick a genuinely good match for this user.

User taste profile:
- All-time favourite movies (manually chosen, highest priority): {fav_str}
- Movies they loved (rated 8-10): {top_str}
- Movies they want to watch: {want_str}
- Movies they skipped (don't want): {dont_str}

Here are {len(pool)} candidate movies to choose from:
{candidates_str}

Task:
1. Pick the single best movie from the list above that matches this user's taste.
2. Write ONE short sentence explaining why — be specific about the theme, mood, or style.
   - The REASON must be based ONLY on the actual movie content described above.
   - Vary your phrasing — avoid starting with "This matches" every time.

Respond ONLY in this exact format (no extra text):
PICK: [exact movie title from the list]
REASON: [one sentence]"""

    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=140,
            temperature=0.7,
        )
        text = response.choices[0].message.content.strip()

        pick_line   = next((l for l in text.splitlines() if l.startswith("PICK:")),   None)
        reason_line = next((l for l in text.splitlines() if l.startswith("REASON:")), None)

        if not pick_line or not reason_line:
            raise ValueError("Unexpected AI response format")

        picked_title = pick_line.replace("PICK:", "").strip().strip('"')
        reason       = reason_line.replace("REASON:", "").strip()

        picked_title_lower = picked_title.lower()
        movie = next((m for m in pool if m["title"].lower() == picked_title_lower), None)
        if movie is None:
            movie = next(
                (m for m in pool if picked_title_lower in m["title"].lower()
                 or m["title"].lower() in picked_title_lower),
                None
            )
        if movie is None:
            raise ValueError(f"AI picked unknown title: {picked_title!r}")

        print(f"[AI Rec] {username} → \"{movie['title']}\" | {reason}")
        return movie, reason

    except Exception as e:
        print(f"[AI Rec] Fallback (error: {e})")
        movie = random.choice(pool)
        top_titles = [t for t, _ in top_rated_shuffled[:2]]
        if top_titles:
            reason = f"Fans of {', '.join(top_titles)} tend to enjoy this."
        else:
            reason = "Trending and highly rated — worth a look."
        return movie, reason


def get_recommended_movie(username: str) -> tuple:
    """
    The main AI recommendation pipeline — called every 4th movie request.
    Fetches candidates from TMDB (popular, discover, top_rated), filters out
    already-seen movies, then delegates to ai_pick_and_explain for personalised selection.
    Returns (movie_dict, reason_str). Returns (None, message) if no candidates found.
    """
    seen = db_get_shown_ids(username)

    def fetch_candidates(source: str, page: int, extra_params: dict = None) -> list:
        """Fetches one TMDB page and filters by poster, vote count, and seen history."""
        params = {"api_key": API_KEY, "language": "en-US", "page": page}
        if extra_params:
            params.update(extra_params)
        try:
            r = requests.get(f"{BASE_URL}/{source}", params=params, timeout=8)
            r.raise_for_status()
            return [m for m in r.json().get("results", [])
                    if m.get("poster_path")
                    and m["id"] not in seen
                    and m.get("vote_count", 0) >= 500]
        except Exception:
            return []

    candidates = []

    # Attempt 1: popular (3 random pages from the first 500)
    pages_tried = set()
    while len(pages_tried) < 3:
        page = random.randint(1, 500)
        if page in pages_tried:
            continue
        pages_tried.add(page)
        candidates.extend(fetch_candidates("movie/popular", page))

    # Attempt 2: discover by a random decade if not enough candidates
    if len(candidates) < 10:
        decade_start = random.choice(range(1970, 2020, 10))
        candidates.extend(fetch_candidates("discover/movie",
            random.randint(1, 100), {
                "sort_by": "vote_count.desc",
                "vote_count.gte": "500",
                "primary_release_date.gte": f"{decade_start}-01-01",
                "primary_release_date.lte": f"{decade_start+9}-12-31",
            }))

    # Attempt 3: top_rated as a last resort
    if not candidates:
        candidates.extend(fetch_candidates("movie/top_rated", random.randint(1, 500)))

    if not candidates:
        return None, "No new movies available right now"

    best_movie, reason = ai_pick_and_explain(username, candidates)

    if best_movie is None:
        best_movie = random.choice(candidates)
        reason = "Trending and highly rated — worth a look."

    db_mark_shown(username, best_movie["id"])
    return best_movie, reason


# ─── Watch Party ──────────────────────────────────────

def create_room(host: str) -> dict:
    """
    Creates a new Watch Party room with a cryptographically secure 6-character code.
    The room is stored in memory only (not persisted to DB) and the host is
    automatically added as the first member.
    """
    code = secrets.token_hex(4)[:6].upper()
    with rooms_lock:
        watch_rooms[code] = {
            "host":            host,
            "members":         [host],
            "movie":           None,
            "movie_picks":     {},
            "ai_recommendation": None,
            "ai_pending":      False,
        }
    print(f"[Room] {host} created room {code}")
    return {"status": "ok", "code": code}


def join_room(username: str, code: str) -> dict:
    """
    Adds a user to an existing room identified by code.
    Sanitises and uppercases the code before lookup.
    Returns an error if the room does not exist.
    """
    code = str(code).strip().upper()[:8]
    with rooms_lock:
        if code not in watch_rooms:
            return {"status": "error", "message": "Room not found"}
        room = watch_rooms[code]
        if username not in room["members"]:
            room["members"].append(username)
    print(f"[Room] {username} joined room {code}")
    return {"status": "ok", "code": code, "host": room["host"],
            "members": room["members"]}


def leave_room(username: str, code: str) -> dict:
    """
    Removes a user from a room. If the host leaves, the entire room is closed
    and all members are effectively kicked. A regular member is simply removed
    from the list and their movie pick is deleted.
    """
    with rooms_lock:
        if code not in watch_rooms:
            return {"status": "error", "message": "Room not found"}
        room = watch_rooms[code]
        if room["host"] == username:
            del watch_rooms[code]
            print(f"[Room] {username} (host) closed room {code}")
            return {"status": "ok", "closed": True}
        if username in room["members"]:
            room["members"].remove(username)
        if username in room["movie_picks"]:
            del room["movie_picks"][username]
        return {"status": "ok", "closed": False}


def get_room(code: str) -> dict:
    """
    Returns a snapshot of the current room state: members, picks, and AI recommendation.
    Called by the client's 3-second polling loop to keep the UI in sync.
    """
    with rooms_lock:
        if code not in watch_rooms:
            return {"status": "error", "message": "Room not found"}
        room = watch_rooms[code]
        return {
            "status":            "ok",
            "code":              code,
            "host":              room["host"],
            "members":           list(room["members"]),
            "movie":             room["movie"],
            "movie_picks":       dict(room["movie_picks"]),
            "ai_recommendation": room["ai_recommendation"],
        }


def set_room_movie(code: str, username: str, movie: dict) -> dict:
    """
    Sets the selected movie for the room. Only the host is authorised to do this.
    Returns an error if the requester is not the host.
    """
    with rooms_lock:
        if code not in watch_rooms:
            return {"status": "error", "message": "Room not found"}
        if watch_rooms[code]["host"] != username:
            return {"status": "error", "message": "Only the host can set the movie"}
        watch_rooms[code]["movie"] = movie
    return {"status": "ok"}


def submit_movie_pick(code: str, username: str, movie_title: str) -> dict:
    """
    Records a member's favourite movie pick for the Watch Party AI recommendation.
    Validates that the title is a non-empty string and that the user is in the room.
    Truncates the title to 256 characters to prevent oversized payloads.
    """
    if not isinstance(movie_title, str) or not movie_title.strip():
        return {"status": "error", "message": "Invalid movie title"}
    movie_title = movie_title.strip()[:256]
    with rooms_lock:
        if code not in watch_rooms:
            return {"status": "error", "message": "Room not found"}
        if username not in watch_rooms[code]["members"]:
            return {"status": "error", "message": "You are not in this room"}
        watch_rooms[code]["movie_picks"][username] = movie_title
    return {"status": "ok"}


def get_ai_group_recommendation(code: str) -> dict:
    """
    Asks Groq / LLaMA to suggest a single movie the whole group would enjoy,
    based on each member's submitted favourite movie pick.
    The ai_pending flag prevents duplicate concurrent requests.
    The result is cached in the room dict and served to all members via polling.
    """
    with rooms_lock:
        if code not in watch_rooms:
            return {"status": "error", "message": "Room not found"}
        room    = watch_rooms[code]
        picks   = dict(room["movie_picks"])
        members = list(room["members"])
        if room["ai_recommendation"]:
            return {"status": "ok", "recommendation": room["ai_recommendation"], "picks": picks}
        if room["ai_pending"]:
            return {"status": "error", "message": "Already processing, please wait..."}
        room["ai_pending"] = True

    if not picks:
        with rooms_lock:
            if code in watch_rooms:
                watch_rooms[code]["ai_pending"] = False
        return {"status": "error", "message": "No one has submitted a movie yet"}

    picks_str = "\n".join(f"- {user} loved: {title}" for user, title in picks.items())
    prompt = (
        f"We are a group of {len(members)} people planning a watch party.\n"
        f"Here are the movies each person loves:\n{picks_str}\n\n"
        f"Based on everyone's taste, recommend ONE movie that the whole group would enjoy together, a movie different from those they chose.\n"
        f"Format your answer exactly like this:\n"
        f"Title: [movie title]\n"
        f"Year: [year]\n"
        f"Why: [two short sentence only]\n"
        f"Only output the formatted answer, nothing else."
    )

    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.choices[0].message.content.strip()
        with rooms_lock:
            if code in watch_rooms:
                watch_rooms[code]["ai_recommendation"] = text
                watch_rooms[code]["ai_pending"]        = False
        return {"status": "ok", "recommendation": text, "picks": picks}
    except Exception as e:
        with rooms_lock:
            if code in watch_rooms:
                watch_rooms[code]["ai_pending"] = False
        return {"status": "error", "message": f"AI error: {str(e)[:80]}"}


def get_random_popular_movie(username: str) -> dict:
    """
    Returns a random unseen movie for the user from TMDB, trying three sources in order:
      1. popular — up to 15 attempts across random pages 1-500 (vote_count >= 100)
      2. discover by random decade 1950-2020 — up to 15 attempts
      3. top_rated — up to 10 attempts across random pages 1-500
    If all sources are exhausted (practically impossible given the catalogue size),
    resets the shown-movies log and tries again recursively.
    Marks the returned movie as shown before returning it.
    """
    seen = db_get_shown_ids(username)

    def fetch_page(source: str, page: int, extra_params: dict = None) -> list:
        """Fetches one TMDB page and filters by poster, vote_count >= 100, and seen."""
        params = {"api_key": API_KEY, "language": "en-US", "page": page}
        if extra_params:
            params.update(extra_params)
        try:
            r = requests.get(f"{BASE_URL}/{source}", params=params, timeout=8)
            r.raise_for_status()
            return [m for m in r.json().get("results", [])
                    if m.get("poster_path")
                    and m["id"] not in seen
                    and m.get("vote_count", 0) >= 100]
        except Exception:
            return []

    for _ in range(15):
        page = random.randint(1, 500)
        candidates = fetch_page("movie/popular", page)
        if candidates:
            movie = random.choice(candidates)
            db_mark_shown(username, movie["id"])
            return movie

    for _ in range(15):
        decade_start = random.choice(range(1950, 2020, 10))
        page = random.randint(1, 100)
        candidates = fetch_page("discover/movie", page, {
            "primary_release_date.gte": f"{decade_start}-01-01",
            "primary_release_date.lte": f"{decade_start + 9}-12-31",
            "sort_by": "vote_count.desc",
            "vote_count.gte": "100",
        })
        if candidates:
            movie = random.choice(candidates)
            db_mark_shown(username, movie["id"])
            return movie

    for _ in range(10):
        page = random.randint(1, 500)
        candidates = fetch_page("movie/top_rated", page)
        if candidates:
            movie = random.choice(candidates)
            db_mark_shown(username, movie["id"])
            return movie

    _reset_shown_movies(username)
    return get_random_popular_movie(username)


def _reset_shown_movies(username: str):
    """
    Clears the shown-movies log for a user, allowing the full movie catalogue
    to be shown again from the beginning.
    Called only as a last-resort fallback in get_random_popular_movie.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM shown_movies_log WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    print(f"[Shown] Reset shown movies for {username}")


def get_user_stats(username: str) -> dict:
    """
    Computes viewing statistics for the user:
      - total, watched, want, and dont counts
      - average personal rating and number of rated movies
      - favourite genre (by frequency across all three lists)
      - favourite decade (by frequency, already_watched only)
      - best-match friend (highest compatibility score among accepted friends)
    Returns all values in a single dict ready for the client to display.
    """
    conn = sqlite3.connect(DB_FILE)
    rows = conn.execute(
        "SELECT status, rating, genre_ids, release_date FROM movies WHERE username = ?",
        (username,)
    ).fetchall()

    watched = [r for r in rows if r[0] == "already_watched"]
    want    = [r for r in rows if r[0] == "want_to_watch"]
    dont    = [r for r in rows if r[0] == "dont_want"]

    ratings    = [r[1] for r in watched if r[1]]
    avg_rating = round(sum(ratings) / len(ratings), 1) if ratings else 0

    genre_count = {}
    for r in rows:
        try:
            genres = json.loads(r[2] or "[]")
        except Exception:
            genres = []
        for gid in genres:
            genre_count[gid] = genre_count.get(gid, 0) + 1
    fav_genre_id = max(genre_count, key=genre_count.get) if genre_count else None
    fav_genre    = GENRE_NAMES.get(fav_genre_id, "Unknown") if fav_genre_id else "N/A"

    decade_count = {}
    for r in rows:
        if r[0] != "already_watched":
            continue
        year_str = (r[3] or "")[:4]
        if year_str.isdigit():
            decade = (int(year_str) // 10) * 10
            decade_count[decade] = decade_count.get(decade, 0) + 1
    fav_decade     = max(decade_count, key=decade_count.get) if decade_count else None
    fav_decade_str = f"{fav_decade}s" if fav_decade else "N/A"

    friends     = get_friends(username)
    best_friend = None
    best_compat = 0
    for friend in friends:
        compat = calculate_compatibility(username, friend)
        if compat["final"] > best_compat:
            best_compat = compat["final"]
            best_friend = friend

    conn.close()
    return {
        "status":        "ok",
        "total":         len(rows),
        "watched_count": len(watched),
        "want_count":    len(want),
        "dont_count":    len(dont),
        "avg_rating":    avg_rating,
        "rated_count":   len(ratings),
        "fav_genre":     fav_genre,
        "fav_decade":    fav_decade_str,
        "best_friend":   best_friend or "N/A",
        "best_compat":   best_compat,
    }


def get_favorite_movies(username: str) -> list:
    """
    Returns the user's 3 manually chosen all-time favourite movie titles.
    Always returns exactly 3 slots, padding with empty strings if fewer were saved.
    """
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT favorite_movies FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if not row:
        return ["", "", ""]
    try:
        favs = json.loads(row[0] or "[]")
        while len(favs) < 3:
            favs.append("")
        return favs[:3]
    except Exception:
        return ["", "", ""]


def save_favorite_movies(username: str, titles: list) -> dict:
    """
    Saves up to 3 favourite movie titles for the user.
    Strips, truncates each title to 256 characters, and pads to exactly 3 slots.
    Stored as a JSON array in the users.favorite_movies column.
    """
    if not isinstance(titles, list):
        return {"status": "error", "message": "Invalid format"}
    cleaned = [str(t).strip()[:256] for t in titles[:3]]
    while len(cleaned) < 3:
        cleaned.append("")
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "UPDATE users SET favorite_movies = ? WHERE username = ?",
        (json.dumps(cleaned), username)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


def search_movies(query: str) -> list:
    """
    Searches TMDB for movies matching the given query string.
    Returns up to 12 results. Sanitises and truncates the query to 100 characters.
    """
    query = str(query).strip()[:100]
    if not query:
        return []
    try:
        r = requests.get(
            f"{BASE_URL}/search/movie",
            params={"api_key": API_KEY, "query": query, "language": "en-US"},
            timeout=8
        )
        r.raise_for_status()
        return r.json().get("results", [])[:12]
    except Exception:
        return []


def get_taste_bio(username: str) -> dict:
    """
    Asks Groq / LLaMA to write a 2-sentence cinematic personality bio for the user,
    written in the style of a film critic describing someone's taste.
    Returns an empty bio if the user has no favourites or top-rated movies yet.
    The bio is used on the user's profile page and on friend profile views.
    """
    profile = get_user_taste_profile(username)

    fav_str  = ", ".join(f'"{t}"' for t in profile["fav_movies"]) or "none yet"
    top_str  = ", ".join(f'"{t}" ({r}/10)' for t, r in profile["top_rated"][:6]) or "none yet"
    want_str = ", ".join(f'"{t}"' for t in profile["want_titles"][:5]) or "none yet"
    dont_str = ", ".join(f'"{t}"' for t in profile["dont_titles"][:5]) or "none yet"

    if fav_str == "none yet" and top_str == "none yet":
        return {"status": "ok", "bio": ""}

    prompt = f"""Based on this user's movie taste, write a short 2-sentence cinematic bio.
It should sound like a film critic describing this person's taste — specific, vivid, and personal.

Favourites: {fav_str}
Loved (rated 8-10): {top_str}
Wants to watch: {want_str}
Skipped: {dont_str}

Rules:
- Exactly 2 sentences, max 40 words total
- Reference specific genres, moods, or themes — not just movie titles
- Make it feel like a personality description, not a list
- Start with something like "A viewer who..." or "Someone drawn to..." or "Gravitates toward..."

Output only the 2 sentences, nothing else."""

    try:
        client = Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=80,
            temperature=0.85,
        )
        bio = response.choices[0].message.content.strip()
        return {"status": "ok", "bio": bio}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def unfriend(username: str, friend: str) -> dict:
    """
    Removes a bidirectional friendship between two users.
    Deletes both rows (username→friend and friend→username) in a single query.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        "DELETE FROM friends WHERE (username = ? AND friend = ?) OR (username = ? AND friend = ?)",
        (username, friend, friend, username)
    )
    conn.commit()
    conn.close()
    return {"status": "ok"}


# ─── Client handler ───────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple):
    """
    Handles a single client connection in its own thread.
    Receives JSON requests, routes by action, and sends JSON responses.

    Security model:
      - LOGIN and REGISTER are open to all clients (subject to rate limiting).
      - Every other action requires a valid session token in the request payload.
      - The authenticated username is always derived from the token server-side;
        the client-supplied username is never trusted for authorisation decisions.
      - On disconnect, the session token is destroyed automatically.
    """
    ip = addr[0]
    print(f"[+] Connected: {addr}")
    session_token = None
    authed_user   = None

    try:
        while True:
            data = conn.recv(4096).decode("utf-8").strip()
            if not data:
                break

            request = json.loads(data)
            action  = request.get("action")

            if action == "REGISTER":
                if not _check_rate_limit(ip):
                    result = {"status": "error",
                              "message": "Too many attempts. Please wait before trying again."}
                else:
                    result = register_user(request.get("username", ""),
                                           request.get("password", ""))
                    if result["status"] != "ok":
                        _record_failure(ip)

            elif action == "LOGIN":
                if not _check_rate_limit(ip):
                    result = {"status": "error",
                              "message": "Too many attempts. Please wait before trying again."}
                else:
                    result = login_user(request.get("username", ""),
                                        request.get("password", ""))
                    if result["status"] == "ok":
                        _record_success(ip)
                        session_token = result["token"]
                        authed_user   = request.get("username", "")
                    else:
                        _record_failure(ip)

            else:
                token = request.get("token")
                if not token:
                    conn.sendall((json.dumps(
                        {"status": "error", "message": "Authentication required"}
                    ) + "\n").encode("utf-8"))
                    continue

                verified_user = _validate_session(token)
                if verified_user is None:
                    conn.sendall((json.dumps(
                        {"status": "error", "message": "Invalid or expired session. Please log in again."}
                    ) + "\n").encode("utf-8"))
                    continue

                username = verified_user

                if action == "GET_MOVIE":
                    try:
                        count = movie_count.get(username, 0) + 1
                        movie_count[username] = count
                        if count % 4 == 0:
                            movie, reason = get_recommended_movie(username)
                        else:
                            movie  = get_random_popular_movie(username)
                            reason = ""
                        if movie is None:
                            result = {"status": "error", "message": "No new movies available right now"}
                        else:
                            result = {
                                "status":       "ok",
                                "id":           movie.get("id"),
                                "title":        movie.get("title", "Unknown"),
                                "release_date": movie.get("release_date", ""),
                                "vote_average": movie.get("vote_average", 0),
                                "vote_count":   movie.get("vote_count", 0),
                                "overview":     movie.get("overview", ""),
                                "poster_path":  movie.get("poster_path", ""),
                                "genre_ids":    movie.get("genre_ids", []),
                                "reason":       reason,
                            }
                    except Exception as e:
                        result = {"status": "error", "message": str(e)}

                elif action == "SAVE_MOVIE":
                    result = save_movie(
                        username, request["movie"],
                        request["movie_status"], request.get("rating")
                    )

                elif action == "GET_MOVIES":
                    target = request.get("target_username", username)
                    if target != username:
                        friends = get_friends(username)
                        if target not in friends:
                            result = {"status": "error", "message": "Not authorized"}
                        else:
                            movies = get_movies_by_status(target, request["movie_status"])
                            result = {"status": "ok", "movies": movies}
                    else:
                        movies = get_movies_by_status(username, request["movie_status"])
                        result = {"status": "ok", "movies": movies}

                elif action == "ADD_FRIEND":
                    result = add_friend(username, request["friend"])
                elif action == "GET_FRIENDS":
                    result = {"status": "ok", "friends": get_friends(username)}
                elif action == "GET_PENDING":
                    result = {"status": "ok", "requests": get_pending_requests(username)}
                elif action == "ACCEPT_FRIEND":
                    result = accept_friend(username, request["requester"])
                elif action == "DECLINE_FRIEND":
                    result = decline_friend(username, request["requester"])

                elif action == "COMPATIBILITY":
                    friend = request.get("friend", "")
                    friends = get_friends(username)
                    if friend not in friends:
                        result = {"status": "error", "message": "Not your friend"}
                    else:
                        result = calculate_compatibility(username, friend)

                elif action == "CREATE_ROOM":
                    result = create_room(username)
                elif action == "JOIN_ROOM":
                    result = join_room(username, request["code"])
                elif action == "LEAVE_ROOM":
                    result = leave_room(username, request["code"])
                elif action == "GET_ROOM":
                    result = get_room(request["code"])
                elif action == "SET_ROOM_MOVIE":
                    result = set_room_movie(request["code"], username, request["movie"])
                elif action == "SUBMIT_MOVIE_PICK":
                    result = submit_movie_pick(request["code"], username, request["movie_title"])
                elif action == "GET_AI_GROUP_RECOMMENDATION":
                    result = get_ai_group_recommendation(request["code"])

                elif action == "GET_STATS":
                    result = get_user_stats(username)
                elif action == "SEARCH_MOVIES":
                    results = search_movies(request.get("query", ""))
                    result  = {"status": "ok", "results": results}
                elif action == "GET_FAVORITE_MOVIES":
                    result = {"status": "ok", "favorites": get_favorite_movies(username)}
                elif action == "SAVE_FAVORITE_MOVIES":
                    result = save_favorite_movies(username, request.get("titles", []))
                elif action == "GET_TASTE_BIO":
                    result = get_taste_bio(username)

                elif action == "GET_FAVORITE_MOVIES_FOR":
                    target = request.get("target_username", "")
                    friends = get_friends(username)
                    if target not in friends:
                        result = {"status": "error", "message": "Not your friend"}
                    else:
                        result = {"status": "ok", "favorites": get_favorite_movies(target)}

                elif action == "GET_TASTE_BIO_FOR":
                    target = request.get("target_username", "")
                    friends = get_friends(username)
                    if target not in friends:
                        result = {"status": "error", "message": "Not your friend"}
                    else:
                        result = get_taste_bio(target)

                elif action == "UNFRIEND":
                    result = unfriend(username, request["friend"])

                else:
                    result = {"status": "error", "message": "Unknown action"}

            conn.sendall((json.dumps(result) + "\n").encode("utf-8"))

    except (ConnectionResetError, BrokenPipeError, json.JSONDecodeError):
        pass
    finally:
        if session_token:
            _destroy_session(session_token)
        conn.close()
        print(f"[-] Disconnected: {addr}")


def main():
    """
    Server entry point.
    Initialises the database, wraps the TCP server socket in SSL using a self-signed
    certificate, then listens for incoming connections and spawns a daemon thread
    for each one via handle_client.
    """
    init_db()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("server.crt", "server.key")

    raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_server.bind((HOST, PORT))
    raw_server.listen()
    server = context.wrap_socket(raw_server, server_side=True)

    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"Server is running! (SSL)")
    print(f"IP address: {local_ip}:{PORT}")
    print("Waiting for connections...\n")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.close()


if __name__ == "__main__":
    main()