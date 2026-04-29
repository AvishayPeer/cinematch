"""
movie_game_gui.py — Client application for Cinematch.

Security model:
  - ServerConnection stores the session token received on login.
  - Every request (except LOGIN/REGISTER) automatically includes {"token": self._token}.
  - GET_MOVIES passes target_username so the server can verify friendship before returning data.
  - The server always derives the authenticated username from the token; the client never
    supplies a username that is trusted for authorisation decisions.
"""

import json
import socket
import threading
import tkinter as tk
import requests
from PIL import Image, ImageTk
from io import BytesIO
import ssl

SERVER_IP  = "127.0.0.1"
IMAGE_BASE = "https://image.tmdb.org/t/p/w500"
PORT       = 5555

BG          = "#0d0d0d"
CARD_BG     = "#1a1a1a"
ACCENT      = "#e50914"
TEXT        = "#ffffff"
SUBTEXT     = "#aaaaaa"
INPUT_BG    = "#2a2a2a"
WANT_CLR    = "#21c55d"
DONT_CLR    = "#e50914"
WATCHED_CLR = "#3b82f6"
MATCH_CLR   = "#7c3aed"
REASON_BG   = "#1e1e2e"
NAV_BG      = "#111111"
PARTY_CLR   = "#f59e0b"
STATS_CLR   = "#10b981"
SEARCH_CLR  = "#0ea5e9"


# ══════════════════════════════════════════════════════
# CLASS 1: ServerConnection
# ══════════════════════════════════════════════════════

class ServerConnection:
    """
    Manages the SSL/TCP socket connection to the server.
    Stores the session token after login and injects it into every subsequent request.
    Each public method corresponds to one protocol action on the server.
    """

    def __init__(self, host: str):
        """
        Opens an SSL connection to the server.
        check_hostname=False and CERT_NONE are appropriate for a self-signed certificate
        in a local network deployment.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        raw_sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock = context.wrap_socket(raw_sock, server_hostname=host)
        self._sock.connect((host, PORT))
        self._sock.settimeout(60)
        self._lock  = threading.Lock()
        self._token = None

    def send(self, payload: dict) -> dict:
        """
        Serialises payload to JSON, sends it to the server, and returns the parsed response.
        Automatically attaches the session token to every action except LOGIN and REGISTER.
        Uses a threading lock to prevent concurrent sends on the same socket.
        Accumulates chunks until a complete, valid JSON object is received.
        """
        if self._token and payload.get("action") not in ("LOGIN", "REGISTER"):
            payload["token"] = self._token

        with self._lock:
            self._sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            data = b""
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    raise ConnectionError("Server closed the connection")
                data += chunk
                try:
                    return json.loads(data.decode("utf-8").strip())
                except json.JSONDecodeError:
                    continue

    def close(self):
        """Closes the underlying socket connection."""
        self._sock.close()

    def register(self, username: str, password: str) -> dict:
        """Sends a REGISTER request to the server."""
        return self.send({"action": "REGISTER", "username": username, "password": password})

    def login(self, username: str, password: str) -> dict:
        """
        Sends a LOGIN request. On success, stores the returned session token
        so it is automatically attached to all future requests.
        """
        result = self.send({"action": "LOGIN", "username": username, "password": password})
        if result.get("status") == "ok":
            self._token = result.get("token")
        return result

    def get_movie(self, username: str) -> dict:
        """
        Requests the next movie to display. The username parameter is kept for
        API symmetry but is not sent — the server derives it from the token.
        """
        return self.send({"action": "GET_MOVIE"})

    def save_movie(self, username: str, movie: dict, status: str, rating: int = None):
        """Sends a SAVE_MOVIE request to persist the user's action for a given movie."""
        self.send({"action": "SAVE_MOVIE",
                   "movie": movie, "movie_status": status, "rating": rating})

    def get_movies(self, username: str, status: str) -> list:
        """
        Fetches the movie list for the given username and status.
        When fetching a friend's list, passes target_username so the server
        can verify that the requester is actually friends with the target.
        """
        return self.send({"action": "GET_MOVIES",
                          "target_username": username,
                          "movie_status": status}).get("movies", [])

    def search_movies(self, query: str) -> list:
        """Searches TMDB via the server for movies matching the query string."""
        return self.send({"action": "SEARCH_MOVIES", "query": query}).get("results", [])

    def get_stats(self, username: str) -> dict:
        """Fetches viewing statistics for the current authenticated user."""
        return self.send({"action": "GET_STATS"})

    def get_favorite_movies(self) -> list:
        """Fetches the 3 manually chosen favourite movies for the current user."""
        return self.send({"action": "GET_FAVORITE_MOVIES"}).get("favorites", ["", "", ""])

    def save_favorite_movies(self, titles: list) -> dict:
        """Saves up to 3 favourite movie titles for the current user."""
        return self.send({"action": "SAVE_FAVORITE_MOVIES", "titles": titles})

    def add_friend(self, username: str, friend: str) -> dict:
        """Sends a friend request to the specified username."""
        return self.send({"action": "ADD_FRIEND", "friend": friend})

    def get_friends(self, username: str) -> list:
        """Returns the list of accepted friends for the current user."""
        return self.send({"action": "GET_FRIENDS"}).get("friends", [])

    def get_pending(self, username: str) -> list:
        """Returns incoming pending friend requests for the current user."""
        return self.send({"action": "GET_PENDING"}).get("requests", [])

    def accept_friend(self, username: str, requester: str) -> dict:
        """Accepts a pending friend request from the given requester."""
        return self.send({"action": "ACCEPT_FRIEND", "requester": requester})

    def decline_friend(self, username: str, requester: str) -> dict:
        """Declines a pending friend request from the given requester."""
        return self.send({"action": "DECLINE_FRIEND", "requester": requester})

    def get_compatibility(self, username: str, friend: str) -> dict:
        """Requests the cinematic compatibility score with a given friend."""
        return self.send({"action": "COMPATIBILITY", "friend": friend})

    def get_favorite_movies_for(self, username: str) -> list:
        """Fetches a friend's favourite movies. The server verifies the friendship."""
        return self.send({"action": "GET_FAVORITE_MOVIES_FOR",
                          "target_username": username}).get("favorites", [])

    def get_taste_bio_for(self, username: str) -> str:
        """Fetches the AI-generated taste bio for a friend. Requires friendship."""
        return self.send({"action": "GET_TASTE_BIO_FOR",
                          "target_username": username}).get("bio", "")

    def unfriend(self, username: str, friend: str) -> dict:
        """Removes the bidirectional friendship with the given user."""
        return self.send({"action": "UNFRIEND", "friend": friend})

    def create_room(self, username: str) -> dict:
        """Creates a new Watch Party room and returns the room code."""
        return self.send({"action": "CREATE_ROOM"})

    def join_room(self, username: str, code: str) -> dict:
        """Joins an existing Watch Party room by code."""
        return self.send({"action": "JOIN_ROOM", "code": code})

    def leave_room(self, username: str, code: str) -> dict:
        """Leaves a Watch Party room. Closes the room if the user is the host."""
        return self.send({"action": "LEAVE_ROOM", "code": code})

    def get_room(self, code: str) -> dict:
        """Fetches the current room state — called every 3 seconds by the polling loop."""
        return self.send({"action": "GET_ROOM", "code": code})

    def submit_movie_pick(self, username: str, code: str, title: str) -> dict:
        """Submits the user's favourite movie pick to the Watch Party room."""
        return self.send({"action": "SUBMIT_MOVIE_PICK", "code": code, "movie_title": title})

    def get_ai_recommendation(self, code: str) -> dict:
        """Requests an AI group movie recommendation for the Watch Party room."""
        return self.send({"action": "GET_AI_GROUP_RECOMMENDATION", "code": code})

    def get_taste_bio(self) -> str:
        """Requests the AI-generated cinematic taste bio for the current user."""
        return self.send({"action": "GET_TASTE_BIO"}).get("bio", "")


# ══════════════════════════════════════════════════════
# CLASS 2: MovieLibrary
# ══════════════════════════════════════════════════════

class MovieLibrary:
    """
    Maintains the user's in-memory movie library across three lists:
    want_to_watch, already_watched, and dont_want.
    Synchronises with the server via ServerConnection but does not write to the DB directly.
    """

    def __init__(self):
        """Initialises three empty lists, one per status category."""
        self._want_to_watch:   list = []
        self._already_watched: list = []
        self._dont_want:       list = []

    @property
    def want_to_watch(self) -> list:
        """Returns a shallow copy of the want-to-watch list to prevent external mutation."""
        return list(self._want_to_watch)

    @property
    def already_watched(self) -> list:
        """Returns a shallow copy of the already-watched list."""
        return list(self._already_watched)

    @property
    def dont_want(self) -> list:
        """Returns a shallow copy of the dont-want list."""
        return list(self._dont_want)

    @property
    def total(self) -> int:
        """Returns the total number of movies across all three lists."""
        return len(self._want_to_watch) + len(self._already_watched) + len(self._dont_want)

    def load(self, want: list, watched: list, dont: list):
        """Replaces all three lists with data loaded from the server at startup."""
        self._want_to_watch   = want
        self._already_watched = watched
        self._dont_want       = dont

    def add(self, movie: dict, status: str, rating: int = None):
        """
        Adds a movie to the appropriate list.
        First removes the movie from all lists by ID to prevent duplicates —
        this allows a movie to change status without appearing twice.
        """
        self._remove_by_id(movie.get("id") or movie.get("movie_id"))
        entry = {
            "movie_id":     movie.get("id") or movie.get("movie_id"),
            "id":           movie.get("id") or movie.get("movie_id"),
            "title":        movie.get("title"),
            "release_date": movie.get("release_date", ""),
            "vote_average": movie.get("vote_average", 0),
            "poster_path":  movie.get("poster_path", ""),
            "genre_ids":    movie.get("genre_ids", []),
            "rating":       rating,
        }
        if status == "want_to_watch":
            self._want_to_watch.append(entry)
        elif status == "already_watched":
            self._already_watched.append(entry)
        elif status == "dont_want":
            self._dont_want.append(entry)

    def score_text(self) -> str:
        """Returns a formatted summary string for display: 'Want: X  Watched: Y  Skip: Z'."""
        return (f"Want: {len(self._want_to_watch)}   "
                f"Watched: {len(self._already_watched)}   "
                f"Skip: {len(self._dont_want)}")

    def _remove_by_id(self, mid):
        """Internal helper — removes a movie by ID from all three lists."""
        if mid is None:
            return
        for lst in (self._want_to_watch, self._already_watched, self._dont_want):
            lst[:] = [m for m in lst
                      if m.get("id") != mid and m.get("movie_id") != mid]

    def movie_data_from(self, current_movie: dict) -> dict:
        """
        Extracts the minimal set of fields needed for a SAVE_MOVIE request.
        Avoids sending the full movie dict to the server.
        """
        return {
            "movie_id":     current_movie.get("id"),
            "title":        current_movie.get("title"),
            "release_date": current_movie.get("release_date"),
            "vote_average": current_movie.get("vote_average"),
            "poster_path":  current_movie.get("poster_path"),
            "genre_ids":    current_movie.get("genre_ids", []),
        }


# ══════════════════════════════════════════════════════
# CLASS 3: Room
# ══════════════════════════════════════════════════════

class Room:
    """
    Tracks the client-side state of the current Watch Party room.
    Records the room code, whether the user is the host, and whether polling is active.
    """

    def __init__(self):
        """Initialises with no active room."""
        self._code:    str  = None
        self._is_host: bool = False
        self._polling: bool = False

    @property
    def code(self) -> str:
        """The current room code, or None if not in a room."""
        return self._code

    @property
    def is_host(self) -> bool:
        """True if the current user created this room and is therefore the host."""
        return self._is_host

    @property
    def is_active(self) -> bool:
        """True if the user is currently in a room."""
        return self._code is not None

    @property
    def polling(self) -> bool:
        """True if the background polling loop is running for this room."""
        return self._polling

    def join(self, code: str, is_host: bool):
        """Records that the user has joined (or created) a room and starts polling."""
        self._code    = code
        self._is_host = is_host
        self._polling = True

    def leave(self):
        """Resets all room state after the user leaves."""
        self._polling = False
        self._code    = None
        self._is_host = False

    def stop_polling(self):
        """Stops the polling loop without clearing the room code — used during cleanup."""
        self._polling = False


# ─── Helpers ──────────────────────────────────────────

def load_poster(path: str, size=(280, 380)):
    """
    Downloads a movie poster from TMDB and converts it to a tkinter-compatible PhotoImage.
    Returns None if the download or conversion fails (e.g. no network, corrupt image).
    """
    try:
        r = requests.get(IMAGE_BASE + path, timeout=8)
        img = Image.open(BytesIO(r.content)).resize(size, Image.LANCZOS)
        return ImageTk.PhotoImage(img)
    except Exception:
        return None


def show_rating_popup(parent, callback):
    """
    Opens a modal dialog for the user to rate a movie on a scale of 1-10.
    Calls callback(rating) with the selected integer rating after the user submits.
    Uses grab_set to block interaction with the parent window until dismissed.
    """
    popup = tk.Toplevel(parent)
    popup.title("Rate this movie")
    popup.configure(bg=BG)
    popup.geometry("320x200")
    popup.resizable(False, False)
    popup.grab_set()

    tk.Label(popup, text="How would you rate this movie?",
             bg=BG, fg=TEXT, font=("Georgia", 12)).pack(pady=(24, 16))

    rating_var = tk.IntVar(value=5)
    frame = tk.Frame(popup, bg=BG)
    frame.pack(fill="x", padx=30)

    lbl = tk.Label(frame, text="5", bg=BG, fg=ACCENT,
                   font=("Georgia", 18, "bold"), width=3)
    lbl.pack(side="right")

    tk.Scale(frame, from_=1, to=10, orient="horizontal",
             variable=rating_var,
             command=lambda v: lbl.config(text=str(int(float(v)))),
             bg=BG, fg=TEXT, troughcolor=INPUT_BG,
             highlightthickness=0, showvalue=False).pack(side="left", expand=True, fill="x")

    tk.Button(popup, text="Submit Rating", bg=WATCHED_CLR, fg=TEXT,
              font=("Georgia", 11, "bold"), relief="flat", cursor="hand2", pady=8,
              command=lambda: [popup.destroy(), callback(rating_var.get())]
              ).pack(pady=(16, 0), padx=30, fill="x")


# ─── Auth Window ──────────────────────────────────────

class AuthWindow(tk.Tk):
    """
    The initial login/register window shown before the main app.
    Manages the server connection, login, and registration flows.
    On successful login, sets self.username and self.conn then destroys itself
    so the calling code can open MovieGameApp.
    """

    def __init__(self):
        """Builds the UI then starts an asynchronous server connection attempt."""
        super().__init__()
        self.title("Cinematch — Login")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.geometry("360x480")
        self.conn     = None
        self.username = None
        self._build_ui()
        self._connect()

    def _connect(self):
        """
        Attempts to open an SSL connection to the server in a daemon thread.
        Updates the status label with progress and any connection errors.
        """
        def go():
            try:
                self.conn = ServerConnection(SERVER_IP)
                self.after(0, lambda: self.status_lbl.config(text=""))
            except Exception as err:
                self.after(0, lambda: self.status_lbl.config(
                    text=f"Cannot connect to server:\n{err}", fg=ACCENT))
        self.status_lbl.config(text="Connecting to server...")
        threading.Thread(target=go, daemon=True).start()

    def _build_ui(self):
        """Constructs the login form: title, username/password fields, and action buttons."""
        tk.Label(self, text="Cinematch", bg=BG, fg=ACCENT,
                 font=("Georgia", 22, "bold")).pack(pady=(40, 4))
        tk.Label(self, text="Login or create an account", bg=BG, fg=SUBTEXT,
                 font=("Georgia", 10)).pack(pady=(0, 30))

        for label, attr, kwargs in [
            ("Username", "username_entry", {}),
            ("Password", "password_entry", {"show": "*"}),
        ]:
            tk.Label(self, text=label, bg=BG, fg=SUBTEXT,
                     font=("Georgia", 10), anchor="w").pack(fill="x", padx=40)
            entry = tk.Entry(self, bg=INPUT_BG, fg=TEXT, insertbackground=TEXT,
                             relief="flat", font=("Georgia", 12), **kwargs)
            entry.pack(fill="x", padx=40, ipady=8, pady=(2, 14))
            setattr(self, attr, entry)

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(fill="x", padx=40)
        tk.Button(btn_frame, text="Login", bg=ACCENT, fg=TEXT,
                  font=("Georgia", 12, "bold"), relief="flat",
                  cursor="hand2", pady=10,
                  command=self._login).pack(side="left", expand=True, fill="x", padx=(0, 6))
        tk.Button(btn_frame, text="Register", bg=INPUT_BG, fg=TEXT,
                  font=("Georgia", 12, "bold"), relief="flat",
                  cursor="hand2", pady=10,
                  command=self._register_user).pack(side="right", expand=True, fill="x", padx=(6, 0))

        self.status_lbl = tk.Label(self, text="", bg=BG, fg=ACCENT,
                                   font=("Georgia", 10), wraplength=280)
        self.status_lbl.pack(pady=(16, 0))

    def _get_fields(self):
        """
        Reads and strips the username and password fields.
        Displays an error and returns (None, None) if either field is empty.
        """
        u = self.username_entry.get().strip()
        p = self.password_entry.get().strip()
        if not u or not p:
            self.status_lbl.config(text="Please fill in all fields.")
            return None, None
        return u, p

    def _login(self):
        """
        Sends a LOGIN request in a daemon thread.
        On success, stores the username and closes the window so MovieGameApp can open.
        On failure, displays the server's error message.
        """
        if not self.conn: return
        u, p = self._get_fields()
        if not u: return
        def go():
            result = self.conn.login(u, p)
            if result["status"] == "ok":
                self.username = u
                self.after(0, self.destroy)
            else:
                self.after(0, lambda: self.status_lbl.config(text=result["message"]))
        threading.Thread(target=go, daemon=True).start()

    def _register_user(self):
        """
        Sends a REGISTER request in a daemon thread.
        Displays the result message in green on success or red on failure.
        """
        if not self.conn: return
        u, p = self._get_fields()
        if not u: return
        def go():
            result = self.conn.register(u, p)
            color = WANT_CLR if result["status"] == "ok" else ACCENT
            self.after(0, lambda: self.status_lbl.config(text=result["message"], fg=color))
        threading.Thread(target=go, daemon=True).start()


# ══════════════════════════════════════════════════════
# CLASS 4: MovieGameApp
# ══════════════════════════════════════════════════════

class MovieGameApp(tk.Tk):
    """
    The main application window with four tabs: Movies, Search, Party, and Profile.
    Owns the ServerConnection, MovieLibrary, and Room objects as shared resources.
    All server calls are made in daemon threads; UI updates are dispatched via self.after().
    """

    def __init__(self, conn: ServerConnection, username: str):
        """Initialises the app, builds the UI layout, and loads user data from the server."""
        super().__init__()
        self.title(f"Cinematch — {username}")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.geometry("420x860")

        self._conn    = conn
        self._library = MovieLibrary()
        self._room    = Room()
        self.username = username

        self._current_movie = None
        self._photo         = None

        self._build_layout()
        self._load_user_data()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_layout(self):
        """
        Creates the top content area and the bottom navigation bar.
        Instantiates a Frame for each of the four tabs and calls their build methods.
        Shows the Movies tab by default.
        """
        self.content = tk.Frame(self, bg=BG)
        self.content.pack(fill="both", expand=True)

        tk.Frame(self, bg="#333333", height=1).pack(fill="x", side="bottom")

        nav = tk.Frame(self, bg=NAV_BG, height=60)
        nav.pack(fill="x", side="bottom")
        nav.pack_propagate(False)

        nav_buttons = [
            ("👤  Profile", STATS_CLR,  self._show_stats_tab,  "_nav_stats_btn"),
            ("🎬  Movies",  ACCENT,     self._show_movies_tab, "_nav_movies_btn"),
            ("🎉  Party",   PARTY_CLR,  self._show_party_tab,  "_nav_party_btn"),
            ("🔍  Search",  SEARCH_CLR, self._show_search_tab, "_nav_search_btn"),
        ]
        for text, _, cmd, attr in nav_buttons:
            btn = tk.Button(nav, text=text, bg=NAV_BG, fg=SUBTEXT,
                            font=("Georgia", 10), relief="flat", bd=0,
                            cursor="hand2", activebackground=NAV_BG, command=cmd)
            btn.pack(side="left", expand=True, fill="both")
            setattr(self, attr, btn)

        self._movies_frame = tk.Frame(self.content, bg=BG)
        self._party_frame  = tk.Frame(self.content, bg=BG)
        self._stats_frame  = tk.Frame(self.content, bg=BG)
        self._search_frame = tk.Frame(self.content, bg=BG)

        self._build_movies_tab()
        self._build_party_tab()
        self._build_stats_tab()
        self._build_search_tab()

        self._show_movies_tab()

    def _switch_tab(self, show_frame, active_btn, active_color, extra=None):
        """
        Hides all tab frames, shows the requested one, and updates nav button colours.
        If an extra callable is provided it is called after the tab is shown
        (used by the Profile tab to trigger _refresh_stats on every visit).
        """
        for f in (self._movies_frame, self._party_frame,
                  self._stats_frame, self._search_frame):
            f.pack_forget()
        show_frame.pack(fill="both", expand=True)

        colors = {
            self._nav_stats_btn:  SUBTEXT,
            self._nav_movies_btn: SUBTEXT,
            self._nav_party_btn:  SUBTEXT,
            self._nav_search_btn: SUBTEXT,
        }
        colors[active_btn] = active_color
        for btn, color in colors.items():
            btn.config(fg=color)

        if extra:
            extra()

    def _show_movies_tab(self):
        """Switches to the Movies tab."""
        self._switch_tab(self._movies_frame, self._nav_movies_btn, ACCENT)

    def _show_party_tab(self):
        """Switches to the Watch Party tab."""
        self._switch_tab(self._party_frame, self._nav_party_btn, PARTY_CLR)

    def _show_stats_tab(self):
        """Switches to the Profile tab and triggers a full data refresh."""
        self._switch_tab(self._stats_frame, self._nav_stats_btn, STATS_CLR,
                         extra=self._refresh_stats)

    def _show_search_tab(self):
        """Switches to the Search tab."""
        self._switch_tab(self._search_frame, self._nav_search_btn, SEARCH_CLR)

    def _build_movies_tab(self):
        """
        Constructs the Movies tab UI:
        centred title, score label, movie card (poster + metadata + AI banner),
        and the three action buttons (Don't Want / Already Watched / Want to Watch).
        """
        f = self._movies_frame

        tk.Label(f, text="Cinematch", bg=BG, fg=ACCENT,
                 font=("Georgia", 18, "bold")).pack(pady=(16, 0))

        self.score_lbl = tk.Label(f, bg=BG, fg=SUBTEXT, font=("Georgia", 9),
                                  text=self._library.score_text())
        self.score_lbl.pack()

        self.card = tk.Frame(f, bg=CARD_BG, bd=0,
                             highlightthickness=1, highlightbackground="#333333")
        self.card.pack(padx=20, pady=6, fill="both", expand=True)

        self.poster_lbl   = tk.Label(self.card, bg=CARD_BG)
        self.title_lbl    = tk.Label(self.card, text="", bg=CARD_BG, fg=TEXT,
                                     font=("Georgia", 15, "bold"),
                                     wraplength=360, justify="center")
        self.meta_lbl     = tk.Label(self.card, text="", bg=CARD_BG, fg=SUBTEXT,
                                     font=("Georgia", 11))
        self.overview_lbl = tk.Label(self.card, text="", bg=CARD_BG, fg=SUBTEXT,
                                     font=("Georgia", 10), wraplength=360, justify="center")
        self.reason_frame = tk.Frame(self.card, bg="#1a1030",
                                     highlightthickness=1, highlightbackground="#5b21b6")
        self.reason_icon  = tk.Label(self.reason_frame, text="✦ AI Pick",
                                     bg="#1a1030", fg="#7c3aed",
                                     font=("Georgia", 8, "bold"))
        self.reason_lbl   = tk.Label(self.reason_frame, text="", bg="#1a1030", fg="#c4b5fd",
                                     font=("Georgia", 9, "italic"),
                                     wraplength=340, justify="center", padx=10, pady=2)
        self.loading_lbl  = tk.Label(self.card, text="", bg=CARD_BG, fg=SUBTEXT,
                                     font=("Georgia", 12))

        btn_frame = tk.Frame(f, bg=BG)
        btn_frame.pack(fill="x", padx=20, pady=(6, 10))

        self.dont_btn = tk.Button(btn_frame, text="Don't Want", bg=DONT_CLR, fg=TEXT,
                                  font=("Georgia", 11, "bold"), relief="flat",
                                  activebackground="#c0070f", cursor="hand2",
                                  bd=0, pady=10, command=self._dont_want)
        self.dont_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))

        self.watched_btn = tk.Button(btn_frame, text="Already Watched", bg=WATCHED_CLR, fg=TEXT,
                                     font=("Georgia", 11, "bold"), relief="flat",
                                     activebackground="#2563eb", cursor="hand2",
                                     bd=0, pady=10, command=self._already_watched)
        self.watched_btn.pack(side="left", expand=True, fill="x", padx=4)

        self.want_btn = tk.Button(btn_frame, text="Want to Watch", bg=WANT_CLR, fg=TEXT,
                                  font=("Georgia", 11, "bold"), relief="flat",
                                  activebackground="#17a34a", cursor="hand2",
                                  bd=0, pady=10, command=self._want_to_watch)
        self.want_btn.pack(side="right", expand=True, fill="x", padx=(4, 0))

    def _load_user_data(self):
        """
        Fetches all three movie lists from the server in a daemon thread at startup.
        Calls _on_data_loaded on the main thread once all data is ready.
        """
        def fetch():
            want    = self._conn.get_movies(self.username, "want_to_watch")
            watched = self._conn.get_movies(self.username, "already_watched")
            dont    = self._conn.get_movies(self.username, "dont_want")
            self.after(0, self._on_data_loaded, want, watched, dont)
        threading.Thread(target=fetch, daemon=True).start()

    def _on_data_loaded(self, want, watched, dont):
        """
        Called on the main thread after startup data has been fetched.
        Initialises the MovieLibrary, updates the score label, triggers the first
        movie load, and starts the friend-request polling loop.
        """
        self._library.load(want, watched, dont)
        self._update_score()
        self._load_next_movie()
        self._start_friend_polling()

    def _set_buttons_state(self, state: str):
        """Enables or disables all three action buttons simultaneously."""
        for btn in (self.want_btn, self.dont_btn, self.watched_btn):
            btn.config(state=state)

    def _load_next_movie(self):
        """
        Clears the current movie card, shows a loading message, disables the action buttons,
        then spawns a daemon thread to fetch the next movie from the server.
        """
        self._set_buttons_state("disabled")
        for w in (self.poster_lbl, self.title_lbl, self.meta_lbl,
                  self.overview_lbl, self.reason_frame):
            w.pack_forget()
        self.loading_lbl.config(text="Finding the best movie for you...")
        self.loading_lbl.pack(expand=True, pady=80)
        threading.Thread(target=self._fetch_movie, daemon=True).start()

    def _fetch_movie(self):
        """
        Calls get_movie on the server connection and downloads the poster concurrently.
        Dispatches _display_movie on success or _show_error on any failure.
        """
        try:
            movie = self._conn.get_movie(self.username)
            if movie.get("status") == "error":
                raise Exception(movie["message"])
            photo = load_poster(movie.get("poster_path", ""))
            self.after(0, self._display_movie, movie, photo)
        except Exception as e:
            self.after(0, self._show_error, str(e))

    def _display_movie(self, movie: dict, photo):
        """
        Renders the movie card: poster (or placeholder), title, year/rating/votes,
        truncated overview, and the AI reason banner if a reason was returned.
        Re-enables the action buttons after rendering.
        """
        self._current_movie = movie
        self._photo = photo
        self.loading_lbl.pack_forget()

        if photo:
            self.poster_lbl.config(image=photo, text="", width=280, height=380)
        else:
            self.poster_lbl.config(image="", text="[no poster]",
                                   font=("Georgia", 20), fg=SUBTEXT)
        self.poster_lbl.pack(pady=(14, 0))

        self.title_lbl.config(text=movie.get("title", "Unknown"))
        self.title_lbl.pack(padx=16, pady=(10, 0))

        year  = movie.get("release_date", "????")[:4]
        avg   = movie.get("vote_average", 0)
        votes = movie.get("vote_count", 0)
        self.meta_lbl.config(text=f"{year}  |  {avg:.1f}/10  ({votes:,} votes)")
        self.meta_lbl.pack(pady=(4, 0))

        overview = movie.get("overview", "")
        if len(overview) > 160:
            overview = overview[:160] + "..."
        self.overview_lbl.config(text=overview)
        self.overview_lbl.pack(padx=16, pady=(6, 6))

        reason = movie.get("reason", "")
        self.reason_frame.pack_forget()
        if reason:
            self.reason_icon.pack(pady=(6, 0))
            self.reason_lbl.config(text=reason)
            self.reason_lbl.pack(pady=(2, 6))
            self.reason_frame.pack(padx=16, pady=(0, 10), fill="x")

        self._set_buttons_state("normal")

    def _show_error(self, msg: str):
        """Displays an error message in the movie card area."""
        self.loading_lbl.config(text=f"Error:\n{msg}")
        self.loading_lbl.pack(expand=True, pady=80)

    def _want_to_watch(self):
        """
        Handles the 'Want to Watch' button press:
        updates the local library, flashes the button, saves to server in a thread,
        then loads the next movie.
        """
        if not self._current_movie: return
        data = self._library.movie_data_from(self._current_movie)
        self._library.add(self._current_movie, "want_to_watch")
        self._flash(self.want_btn, WANT_CLR)
        self._update_score()
        threading.Thread(target=self._conn.save_movie,
                         args=(self.username, data, "want_to_watch"), daemon=True).start()
        self._load_next_movie()

    def _dont_want(self):
        """
        Handles the 'Don't Want' button press:
        updates the local library, flashes the button, saves to server, loads next movie.
        """
        if not self._current_movie: return
        data = self._library.movie_data_from(self._current_movie)
        self._library.add(self._current_movie, "dont_want")
        self._flash(self.dont_btn, DONT_CLR)
        self._update_score()
        threading.Thread(target=self._conn.save_movie,
                         args=(self.username, data, "dont_want"), daemon=True).start()
        self._load_next_movie()

    def _already_watched(self):
        """
        Handles the 'Already Watched' button press.
        Opens a rating popup first; once the user submits a rating, saves to server
        and loads the next movie.
        """
        if not self._current_movie: return
        data = self._library.movie_data_from(self._current_movie)
        def on_rating(rating: int):
            self._library.add(self._current_movie, "already_watched", rating)
            self._flash(self.watched_btn, WATCHED_CLR)
            self._update_score()
            threading.Thread(target=self._conn.save_movie,
                             args=(self.username, data, "already_watched", rating),
                             daemon=True).start()
            self._load_next_movie()
        show_rating_popup(self, on_rating)

    def _update_score(self):
        """Updates the score label to reflect the current MovieLibrary counts."""
        self.score_lbl.config(text=self._library.score_text())

    def _flash(self, btn, color):
        """Briefly flashes a button white then restores its original colour as visual feedback."""
        btn.config(bg="white")
        self.after(100, lambda: btn.config(bg=color))

    def _show_my_list_window(self):
        """
        Opens a separate window with three tabs showing the user's personal movie lists.
        Uses the in-memory MovieLibrary — no additional server request is made.
        """
        win = tk.Toplevel(self)
        win.title("My Movie List")
        win.configure(bg=BG)
        win.geometry("440x580")
        win.resizable(False, False)

        tk.Label(win, text="My Movie List", bg=BG, fg=ACCENT,
                 font=("Georgia", 16, "bold")).pack(pady=(20, 4))

        tab_frame     = tk.Frame(win, bg=BG)
        tab_frame.pack(fill="x", padx=20, pady=(0, 8))
        content_frame = tk.Frame(win, bg=BG)
        content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        tab_btns = []

        def show_tab(key, active_btn, show_r=False):
            for w in content_frame.winfo_children(): w.destroy()
            for b in tab_btns: b.config(bg=INPUT_BG)
            active_btn.config(bg=ACCENT)
            movies = {
                "want_to_watch":   self._library.want_to_watch,
                "already_watched": self._library.already_watched,
                "dont_want":       self._library.dont_want,
            }[key]
            if not movies:
                tk.Label(content_frame, text="No movies here yet...",
                         bg=BG, fg=SUBTEXT, font=("Georgia", 11)).pack(expand=True)
                return
            self._render_movie_list(content_frame, movies, show_rating=show_r)

        tabs = [("Want to Watch", "want_to_watch", False),
                ("Already Watched", "already_watched", True),
                ("Don't Want", "dont_want", False)]

        for label, key, show_r in tabs:
            b = tk.Button(tab_frame, text=label, bg=INPUT_BG, fg=TEXT,
                          font=("Georgia", 10), relief="flat", cursor="hand2",
                          padx=8, pady=6)
            b.pack(side="left", expand=True, fill="x", padx=2)
            tab_btns.append(b)

        for i, (_, key, show_r) in enumerate(tabs):
            btn = tab_btns[i]
            btn.config(command=lambda k=key, b=btn, r=show_r: show_tab(k, b, r))

        show_tab("want_to_watch", tab_btns[0], False)

    def _render_movie_list(self, parent, movies: list, show_rating=False):
        """
        Renders a scrollable list of movies inside the given parent frame.
        Shows title, year, TMDB rating, and optionally the user's personal rating.
        """
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="both", expand=True)

        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")

        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)

        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")

        for i, movie in enumerate(movies, 1):
            row = tk.Frame(inner, bg=CARD_BG,
                           highlightthickness=1, highlightbackground="#333")
            row.pack(fill="x", pady=3, padx=2)
            left = tk.Frame(row, bg=CARD_BG)
            left.pack(side="left", fill="both", expand=True, padx=10, pady=8)

            tk.Label(left, text=f"{i}. {movie.get('title', 'Unknown')}",
                     bg=CARD_BG, fg=TEXT, font=("Georgia", 11, "bold"),
                     anchor="w", wraplength=280).pack(fill="x")

            year = str(movie.get("release_date", ""))[:4]
            avg  = movie.get("vote_average", 0)
            meta = f"{year}  |  TMDB: {avg:.1f}/10"
            if show_rating and movie.get("rating"):
                meta += f"  |  My rating: {movie['rating']}/10"
            tk.Label(left, text=meta, bg=CARD_BG, fg=SUBTEXT,
                     font=("Georgia", 9), anchor="w").pack(fill="x")

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        outer.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

    def _show_friends_window(self):
        """
        Opens the Friends management window.
        Allows adding friends, viewing the friend list, and accessing
        Match %, Profile, and Unfriend actions for each friend.
        """
        win = tk.Toplevel(self)
        win.title("Friends")
        win.configure(bg=BG)
        win.geometry("400x580")
        win.resizable(False, False)

        tk.Label(win, text="Friends", bg=BG, fg=ACCENT,
                 font=("Georgia", 16, "bold")).pack(pady=(20, 4))

        add_frame = tk.Frame(win, bg=BG)
        add_frame.pack(fill="x", padx=20, pady=(8, 4))

        entry = tk.Entry(add_frame, bg=INPUT_BG, fg=TEXT,
                         insertbackground=TEXT, relief="flat", font=("Georgia", 11))
        entry.pack(side="left", expand=True, fill="x", ipady=7, padx=(0, 8))
        entry.insert(0, "Enter username...")
        entry.bind("<FocusIn>",  lambda e: entry.delete(0, "end") if entry.get() == "Enter username..." else None)
        entry.bind("<FocusOut>", lambda e: entry.insert(0, "Enter username...") if not entry.get() else None)

        status_lbl = tk.Label(win, text="", bg=BG, fg=ACCENT, font=("Georgia", 10))
        status_lbl.pack()

        outer = tk.Frame(win, bg=BG)
        outer.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")

        def do_unfriend(friend, row):
            """Sends an UNFRIEND request and refreshes the list on success."""
            def send():
                result = self._conn.unfriend(self.username, friend)
                if result.get("status") == "ok":
                    self.after(0, reload)
                else:
                    self.after(0, lambda: status_lbl.config(
                        text=result.get("message", "Error"), fg=ACCENT))
            threading.Thread(target=send, daemon=True).start()

        def reload():
            """Clears and reloads the friend list from the server."""
            for w in inner.winfo_children(): w.destroy()
            def fetch():
                friends = self._conn.get_friends(self.username)
                self.after(0, render, friends)
            threading.Thread(target=fetch, daemon=True).start()

        def render(friends):
            """Renders one row per friend with Match %, Unfriend, and Profile buttons."""
            if not friends:
                tk.Label(inner, text="No friends yet...", bg=BG, fg=SUBTEXT,
                         font=("Georgia", 11)).pack(pady=20)
                return
            for friend in friends:
                row = tk.Frame(inner, bg=CARD_BG,
                               highlightthickness=1, highlightbackground="#333")
                row.pack(fill="x", pady=4, padx=4)
                tk.Label(row, text=f"  {friend}", bg=CARD_BG, fg=TEXT,
                         font=("Georgia", 11), anchor="w",
                         padx=12, pady=10).pack(side="left")
                tk.Button(row, text="Match %", bg=MATCH_CLR, fg=TEXT,
                          font=("Georgia", 9), relief="flat", cursor="hand2",
                          padx=8, pady=4,
                          command=lambda f=friend: self._show_compatibility(f)
                          ).pack(side="right", padx=(0, 4))
                tk.Button(row, text="Unfriend", bg=DONT_CLR, fg=TEXT,
                          font=("Georgia", 9), relief="flat", cursor="hand2",
                          padx=8, pady=4,
                          command=lambda f=friend: do_unfriend(f, row)
                          ).pack(side="right", padx=(0, 4))
                tk.Button(row, text="Profile", bg=INPUT_BG, fg=TEXT,
                          font=("Georgia", 9), relief="flat", cursor="hand2",
                          padx=8, pady=4,
                          command=lambda f=friend: self._show_friend_profile(f)
                          ).pack(side="right", padx=(0, 4))
            canvas.configure(scrollregion=canvas.bbox("all"))

        def do_add():
            """Sends a friend request for the typed username and refreshes on success."""
            friend = entry.get().strip()
            if not friend or friend == "Enter username...": return
            def send():
                result = self._conn.add_friend(self.username, friend)
                color = WANT_CLR if result["status"] == "ok" else ACCENT
                self.after(0, lambda: status_lbl.config(text=result["message"], fg=color))
                if result["status"] == "ok":
                    self.after(0, reload)
            threading.Thread(target=send, daemon=True).start()

        tk.Button(add_frame, text="Add", bg=ACCENT, fg=TEXT,
                  font=("Georgia", 11, "bold"), relief="flat",
                  cursor="hand2", padx=12, pady=7,
                  command=do_add).pack(side="right")

        tk.Label(win, text="Your friends", bg=BG, fg=SUBTEXT,
                 font=("Georgia", 10)).pack(anchor="w", padx=20, pady=(0, 4))

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        reload()

    def _show_compatibility(self, friend: str):
        """
        Opens a window showing the cinematic compatibility score with a friend.
        Displays the overall percentage and a breakdown of all three scoring layers.
        """
        win = tk.Toplevel(self)
        win.title(f"Match with {friend}")
        win.configure(bg=BG)
        win.geometry("340x400")
        win.resizable(False, False)

        tk.Label(win, text=f"Match with {friend}", bg=BG, fg=ACCENT,
                 font=("Georgia", 15, "bold")).pack(pady=(24, 4))
        loading = tk.Label(win, text="Calculating...", bg=BG, fg=SUBTEXT,
                           font=("Georgia", 11))
        loading.pack(expand=True)

        def fetch():
            result = self._conn.get_compatibility(self.username, friend)
            self.after(0, render, result)

        def render(result):
            """Renders the large percentage score and the three-layer breakdown cards."""
            loading.pack_forget()
            final = result.get("final", 0)
            color = WANT_CLR if final >= 70 else ("#f59e0b" if final >= 40 else DONT_CLR)
            tk.Label(win, text=f"{final}%", bg=BG, fg=color,
                     font=("Georgia", 52, "bold")).pack(pady=(8, 0))
            tk.Label(win, text="overall match", bg=BG, fg=SUBTEXT,
                     font=("Georgia", 10)).pack(pady=(0, 16))
            card = tk.Frame(win, bg=CARD_BG,
                            highlightthickness=1, highlightbackground="#333")
            card.pack(fill="x", padx=24, pady=(0, 16))
            for label, score, sub, weight in [
                ("Rating Similarity",     result.get("layer1", 0), f"{result.get('rated_count', 0)} rated by both", "70%"),
                ("Want to Watch Overlap", result.get("layer2", 0), f"{result.get('want_count', 0)} compared", "20%"),
                ("Shared Dislikes",       result.get("layer3", 0), f"{result.get('dont_count', 0)} compared", "10%"),
            ]:
                row = tk.Frame(card, bg=CARD_BG)
                row.pack(fill="x", padx=12, pady=(8, 0))
                tk.Label(row, text=label, bg=CARD_BG, fg=TEXT,
                         font=("Georgia", 10, "bold"), anchor="w").pack(fill="x")
                info = tk.Frame(row, bg=CARD_BG)
                info.pack(fill="x", pady=(0, 6))
                tk.Label(info, text=sub, bg=CARD_BG, fg=SUBTEXT,
                         font=("Georgia", 8), anchor="w").pack(side="left")
                tk.Label(info, text=f"{score}%  (weight {weight})",
                         bg=CARD_BG, fg=ACCENT,
                         font=("Georgia", 9, "bold")).pack(side="right")

        threading.Thread(target=fetch, daemon=True).start()

    def _show_friend_list(self, friend: str):
        """
        Opens a window showing a friend's want-to-watch and already-watched lists.
        Loads the data from the server in a background thread.
        """
        win = tk.Toplevel(self)
        win.title(f"{friend}'s list")
        win.configure(bg=BG)
        win.geometry("440x540")
        win.resizable(False, False)

        tk.Label(win, text=f"{friend}'s list", bg=BG, fg=ACCENT,
                 font=("Georgia", 16, "bold")).pack(pady=(20, 4))
        loading = tk.Label(win, text="Loading...", bg=BG, fg=SUBTEXT,
                           font=("Georgia", 11))
        loading.pack(expand=True)

        tab_frame   = tk.Frame(win, bg=BG)
        content_frm = tk.Frame(win, bg=BG)

        def fetch():
            want    = self._conn.get_movies(friend, "want_to_watch")
            watched = self._conn.get_movies(friend, "already_watched")
            self.after(0, render, want, watched)

        def render(want, watched):
            loading.pack_forget()
            tab_frame.pack(fill="x", padx=20, pady=(0, 8))
            content_frm.pack(fill="both", expand=True, padx=20, pady=(0, 16))

            tab_btns = []

            def show_tab(movies, active_btn, show_r=False):
                for w in content_frm.winfo_children(): w.destroy()
                for b in tab_btns: b.config(bg=INPUT_BG)
                active_btn.config(bg=ACCENT)
                if not movies:
                    tk.Label(content_frm, text="No movies here yet...",
                             bg=BG, fg=SUBTEXT, font=("Georgia", 11)).pack(expand=True)
                    return
                self._render_movie_list(content_frm, movies, show_rating=show_r)

            for lbl in ["Want to Watch", "Already Watched"]:
                b = tk.Button(tab_frame, text=lbl, bg=INPUT_BG, fg=TEXT,
                              font=("Georgia", 10), relief="flat", cursor="hand2",
                              padx=8, pady=6)
                b.pack(side="left", expand=True, fill="x", padx=2)
                tab_btns.append(b)

            tab_btns[0].config(command=lambda: show_tab(want,    tab_btns[0]))
            tab_btns[1].config(command=lambda: show_tab(watched, tab_btns[1], True))
            show_tab(want, tab_btns[0])

        threading.Thread(target=fetch, daemon=True).start()

    def _show_friend_profile(self, friend: str):
        """
        Opens a full profile view for a friend:
        avatar, name, compatibility score, AI taste bio, favourite movies,
        and buttons to view their want-to-watch and already-watched lists.
        All data is fetched in a single background thread.
        """
        win = tk.Toplevel(self)
        win.title(f"{friend}'s Profile")
        win.configure(bg=BG)
        win.geometry("400x620")
        win.resizable(False, False)

        outer = tk.Frame(win, bg=BG)
        outer.pack(fill="both", expand=True)
        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        outer.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        header = tk.Frame(inner, bg=BG)
        header.pack(fill="x", padx=24, pady=(24, 0))

        av = tk.Canvas(header, width=72, height=72, bg=BG, highlightthickness=0)
        av.pack(side="left", padx=(0, 16))
        av.create_oval(2, 2, 70, 70, fill=MATCH_CLR, outline="")
        av.create_text(36, 36, text=friend[0].upper(), fill=BG, font=("Georgia", 28, "bold"))

        name_block = tk.Frame(header, bg=BG)
        name_block.pack(side="left", fill="y")
        tk.Label(name_block, text=friend, bg=BG, fg=TEXT,
                 font=("Georgia", 20, "bold"), anchor="w").pack(anchor="w")
        tk.Label(name_block, text="Cinematch member", bg=BG, fg=SUBTEXT,
                 font=("Georgia", 10), anchor="w").pack(anchor="w")

        compat_lbl = tk.Label(inner, text="Calculating match...", bg=BG, fg=SUBTEXT,
                              font=("Georgia", 10))
        compat_lbl.pack(pady=(12, 0))

        bio_frame = tk.Frame(inner, bg=CARD_BG,
                             highlightthickness=1, highlightbackground="#333")
        bio_frame.pack(fill="x", padx=24, pady=(12, 0))
        bio_lbl = tk.Label(bio_frame, text="✦ Loading taste profile...",
                           bg=CARD_BG, fg="#a78bfa",
                           font=("Georgia", 10, "italic"),
                           wraplength=320, justify="left", padx=14, pady=12)
        bio_lbl.pack(fill="x")

        tk.Frame(inner, bg="#333333", height=1).pack(fill="x", padx=24, pady=(16, 12))

        tk.Label(inner, text="⭐  Favourite Movies", bg=BG, fg=STATS_CLR,
                 font=("Georgia", 12, "bold"), anchor="w").pack(fill="x", padx=24, pady=(0, 8))

        fav_frame = tk.Frame(inner, bg=CARD_BG,
                             highlightthickness=1, highlightbackground="#333")
        fav_frame.pack(fill="x", padx=24, pady=(0, 4))
        fav_lbl = tk.Label(fav_frame, text="Loading...", bg=CARD_BG, fg=SUBTEXT,
                           font=("Georgia", 10), padx=14, pady=10, anchor="w")
        fav_lbl.pack(fill="x")

        tk.Frame(inner, bg="#333333", height=1).pack(fill="x", padx=24, pady=(12, 12))

        tk.Label(inner, text="🎬  Movie Lists", bg=BG, fg=STATS_CLR,
                 font=("Georgia", 12, "bold"), anchor="w").pack(fill="x", padx=24, pady=(0, 8))

        lists_frame = tk.Frame(inner, bg=BG)
        lists_frame.pack(fill="x", padx=24, pady=(0, 20))

        want_btn = tk.Button(lists_frame, text="Want to Watch (loading...)",
                             bg=WANT_CLR, fg=TEXT,
                             font=("Georgia", 10, "bold"), relief="flat", cursor="hand2", pady=8)
        want_btn.pack(fill="x", pady=(0, 6))

        watched_btn = tk.Button(lists_frame, text="Already Watched (loading...)",
                                bg=WATCHED_CLR, fg=TEXT,
                                font=("Georgia", 10, "bold"), relief="flat", cursor="hand2", pady=8)
        watched_btn.pack(fill="x")

        def fetch():
            """Fetches compatibility, favourites, movie lists, and bio in one thread."""
            try:
                compat  = self._conn.get_compatibility(self.username, friend)
                favs    = self._conn.get_favorite_movies_for(friend)
                want    = self._conn.get_movies(friend, "want_to_watch")
                watched = self._conn.get_movies(friend, "already_watched")
                bio     = self._conn.get_taste_bio_for(friend)
                self.after(0, populate, compat, favs, want, watched, bio)
            except Exception as e:
                self.after(0, lambda err=e: compat_lbl.config(text=f"Error: {err}", fg=ACCENT))

        def populate(compat, favs, want, watched, bio):
            """Fills all UI elements with the fetched data."""
            final = compat.get("final", 0)
            color = WANT_CLR if final >= 70 else ("#f59e0b" if final >= 40 else DONT_CLR)
            compat_lbl.config(text=f"🤝  {final}% match with you", fg=color,
                              font=("Georgia", 12, "bold"))

            if bio:
                bio_lbl.config(text=f"✦  {bio}")
            else:
                bio_frame.pack_forget()

            filled = [f for f in favs if f.strip()]
            if filled:
                fav_lbl.config(
                    text="\n".join(f"  #{i+1}  {t}" for i, t in enumerate(filled)),
                    justify="left")
            else:
                fav_lbl.config(text="  No favourites set yet")

            want_btn.config(
                text=f"Want to Watch  ({len(want)})",
                command=lambda: self._show_friend_list_popup(friend, want, "Want to Watch"))
            watched_btn.config(
                text=f"Already Watched  ({len(watched)})",
                command=lambda: self._show_friend_list_popup(friend, watched, "Already Watched", show_rating=True))

        threading.Thread(target=fetch, daemon=True).start()

    def _show_friend_list_popup(self, friend: str, movies: list, title: str, show_rating=False):
        """
        Opens a compact window showing a pre-fetched list of a friend's movies.
        Receives the movie list as a parameter — no additional server request is made.
        """
        win = tk.Toplevel(self)
        win.title(f"{friend} — {title}")
        win.configure(bg=BG)
        win.geometry("420x500")
        win.resizable(False, False)
        tk.Label(win, text=title, bg=BG, fg=ACCENT,
                 font=("Georgia", 15, "bold")).pack(pady=(16, 8))
        frame = tk.Frame(win, bg=BG)
        frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        if not movies:
            tk.Label(frame, text="No movies here yet...",
                     bg=BG, fg=SUBTEXT, font=("Georgia", 11)).pack(expand=True)
            return
        self._render_movie_list(frame, movies, show_rating=show_rating)

    def _start_friend_polling(self):
        """
        Starts a recurring 5-second polling loop that checks for incoming friend requests.
        For each pending requester found, opens a friend-request popup on the main thread.
        """
        def poll():
            try:
                pending = self._conn.get_pending(self.username)
                for requester in pending:
                    self.after(0, self._show_friend_request_popup, requester)
            except Exception:
                pass
            self.after(5000, self._start_friend_polling)
        self.after(5000, lambda: threading.Thread(target=poll, daemon=True).start())

    def _show_friend_request_popup(self, requester: str):
        """
        Displays a modal dialog for an incoming friend request with Accept and Decline buttons.
        Uses grab_set to require the user to respond before continuing.
        """
        popup = tk.Toplevel(self)
        popup.title("Friend Request")
        popup.configure(bg=BG)
        popup.geometry("300x180")
        popup.resizable(False, False)
        popup.grab_set()

        tk.Label(popup, text="Friend Request", bg=BG, fg=ACCENT,
                 font=("Georgia", 14, "bold")).pack(pady=(20, 4))
        tk.Label(popup, text=f"{requester} wants to be your friend",
                 bg=BG, fg=TEXT, font=("Georgia", 11)).pack(pady=(0, 20))

        btn_frame = tk.Frame(popup, bg=BG)
        btn_frame.pack(fill="x", padx=20)

        def accept():
            threading.Thread(target=self._conn.accept_friend,
                             args=(self.username, requester), daemon=True).start()
            popup.destroy()

        def decline():
            threading.Thread(target=self._conn.decline_friend,
                             args=(self.username, requester), daemon=True).start()
            popup.destroy()

        tk.Button(btn_frame, text="Accept", bg=WANT_CLR, fg=TEXT,
                  font=("Georgia", 11, "bold"), relief="flat", cursor="hand2", pady=8,
                  command=accept).pack(side="left", expand=True, fill="x", padx=(0, 6))
        tk.Button(btn_frame, text="Decline", bg=DONT_CLR, fg=TEXT,
                  font=("Georgia", 11, "bold"), relief="flat", cursor="hand2", pady=8,
                  command=decline).pack(side="right", expand=True, fill="x", padx=(6, 0))

    def _build_party_tab(self):
        """Creates the Watch Party tab container and shows the initial lobby view."""
        self._party_content = tk.Frame(self._party_frame, bg=BG)
        self._party_content.pack(fill="both", expand=True)
        self._build_party_lobby()

    def _build_party_lobby(self):
        """
        Builds the Watch Party lobby UI:
        a Create Room card and a Join Room card with a code entry field.
        """
        for w in self._party_content.winfo_children(): w.destroy()

        tk.Label(self._party_content, text="Watch Party", bg=BG, fg=PARTY_CLR,
                 font=("Georgia", 18, "bold")).pack(pady=(24, 4))
        tk.Label(self._party_content, text="Watch movies together with friends",
                 bg=BG, fg=SUBTEXT, font=("Georgia", 10)).pack(pady=(0, 24))

        create_frame = tk.Frame(self._party_content, bg=CARD_BG,
                                highlightthickness=1, highlightbackground="#333")
        create_frame.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(create_frame, text="Create a new room", bg=CARD_BG, fg=TEXT,
                 font=("Georgia", 12, "bold")).pack(padx=16, pady=(14, 4))
        tk.Label(create_frame,
                 text="You'll be the host and get a room code\nto share with friends.",
                 bg=CARD_BG, fg=SUBTEXT, font=("Georgia", 9),
                 justify="center").pack(padx=16, pady=(0, 10))
        create_status = tk.Label(create_frame, text="", bg=CARD_BG, fg=WANT_CLR,
                                 font=("Georgia", 10, "bold"))
        create_status.pack()

        def do_create():
            """Creates a room and navigates to the room view on success."""
            def go():
                result = self._conn.create_room(self.username)
                if result["status"] == "ok":
                    self._room.join(result["code"], is_host=True)
                    self.after(0, lambda: self._build_party_room())
                else:
                    self.after(0, lambda: create_status.config(
                        text=result["message"], fg=ACCENT))
            threading.Thread(target=go, daemon=True).start()

        tk.Button(create_frame, text="Create Room", bg=PARTY_CLR, fg=BG,
                  font=("Georgia", 11, "bold"), relief="flat", cursor="hand2",
                  pady=8, command=do_create).pack(fill="x", padx=16, pady=(4, 16))

        join_frame = tk.Frame(self._party_content, bg=CARD_BG,
                              highlightthickness=1, highlightbackground="#333")
        join_frame.pack(fill="x", padx=24)
        tk.Label(join_frame, text="Join an existing room", bg=CARD_BG, fg=TEXT,
                 font=("Georgia", 12, "bold")).pack(padx=16, pady=(14, 8))
        code_entry = tk.Entry(join_frame, bg=INPUT_BG, fg=TEXT,
                              insertbackground=TEXT, relief="flat",
                              font=("Georgia", 13), justify="center")
        code_entry.pack(fill="x", padx=16, ipady=8)
        join_status = tk.Label(join_frame, text="", bg=CARD_BG, fg=ACCENT,
                               font=("Georgia", 10))
        join_status.pack(pady=(4, 0))

        def do_join():
            """Joins the room for the entered code and navigates to the room view."""
            code = code_entry.get().strip().upper()
            if not code:
                join_status.config(text="Please enter a room code.")
                return
            def go():
                result = self._conn.join_room(self.username, code)
                if result["status"] == "ok":
                    self._room.join(code, is_host=False)
                    self.after(0, self._build_party_room)
                else:
                    self.after(0, lambda: join_status.config(text=result["message"]))
            threading.Thread(target=go, daemon=True).start()

        tk.Button(join_frame, text="Join Room", bg=WATCHED_CLR, fg=TEXT,
                  font=("Georgia", 11, "bold"), relief="flat", cursor="hand2",
                  pady=8, command=do_join).pack(fill="x", padx=16, pady=(8, 16))

    def _build_party_room(self):
        """
        Builds the active Watch Party room UI:
        member list, movie-pick submission, picks display, AI recommendation button
        (host only), leave button, and a 3-second polling loop via update_ui.
        """
        for w in self._party_content.winfo_children(): w.destroy()

        code    = self._room.code
        is_host = self._room.is_host

        outer = tk.Frame(self._party_content, bg=BG)
        outer.pack(fill="both", expand=True)

        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        outer.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        tk.Label(inner, text=f"Room: {code}", bg=BG, fg=PARTY_CLR,
                 font=("Georgia", 18, "bold")).pack(pady=(20, 2))
        tk.Label(inner, text="You are the host" if is_host else "You are a guest",
                 bg=BG, fg=SUBTEXT, font=("Georgia", 10)).pack(pady=(0, 12))

        tk.Label(inner, text="Members", bg=BG, fg=TEXT,
                 font=("Georgia", 11, "bold")).pack(anchor="w", padx=24)
        members_lbl = tk.Label(inner, text="", bg=CARD_BG, fg=TEXT,
                               font=("Georgia", 11), wraplength=360,
                               justify="left", padx=12, pady=8)
        members_lbl.pack(fill="x", padx=24, pady=(4, 12))

        tk.Label(inner, text="What movie did you love?", bg=BG, fg=TEXT,
                 font=("Georgia", 11, "bold")).pack(anchor="w", padx=24)
        pick_frame = tk.Frame(inner, bg=BG)
        pick_frame.pack(fill="x", padx=24, pady=(4, 0))
        pick_entry = tk.Entry(pick_frame, bg=INPUT_BG, fg=TEXT,
                              insertbackground=TEXT, relief="flat", font=("Georgia", 11))
        pick_entry.pack(side="left", expand=True, fill="x", ipady=7, padx=(0, 8))
        pick_status = tk.Label(inner, text="", bg=BG, fg=WANT_CLR, font=("Georgia", 9))
        pick_status.pack(anchor="w", padx=24)

        def do_submit_pick():
            """Sends the movie title from the entry field as the user's pick."""
            title = pick_entry.get().strip()
            if not title: return
            def go():
                result = self._conn.submit_movie_pick(self.username, code, title)
                if result["status"] == "ok":
                    self.after(0, lambda: pick_status.config(
                        text=f"Submitted: {title}", fg=WANT_CLR))
            threading.Thread(target=go, daemon=True).start()

        tk.Button(pick_frame, text="Submit", bg=WANT_CLR, fg=TEXT,
                  font=("Georgia", 10, "bold"), relief="flat",
                  cursor="hand2", padx=10, pady=7,
                  command=do_submit_pick).pack(side="right")

        tk.Label(inner, text="Submissions so far", bg=BG, fg=TEXT,
                 font=("Georgia", 11, "bold")).pack(anchor="w", padx=24, pady=(12, 0))
        picks_lbl = tk.Label(inner, text="None yet", bg=CARD_BG, fg=SUBTEXT,
                             font=("Georgia", 10), wraplength=360,
                             justify="left", padx=12, pady=8)
        picks_lbl.pack(fill="x", padx=24, pady=(4, 0))

        ai_lbl    = tk.Label(inner, text="", bg=REASON_BG, fg="#a78bfa",
                             font=("Georgia", 14, "bold"), wraplength=360,
                             justify="center", padx=12, pady=16)
        ai_status = tk.Label(inner, text="", bg=BG, fg=SUBTEXT, font=("Georgia", 9))

        if is_host:
            def do_ai():
                """Requests an AI group recommendation and displays the result when ready."""
                ai_lbl.pack_forget()
                ai_status.config(text="Asking AI...")
                ai_status.pack(pady=(4, 0))
                ai_button.config(state="disabled")
                def go():
                    result = self._conn.get_ai_recommendation(code)
                    self.after(0, show_ai_result, result)
                threading.Thread(target=go, daemon=True).start()

            def show_ai_result(result):
                """Shows the AI recommendation text or an error message."""
                ai_status.pack_forget()
                self.after(30000, lambda: ai_button.config(state="normal"))
                if result["status"] == "ok":
                    ai_lbl.config(text=result["recommendation"])
                    ai_lbl.pack(fill="x", padx=24, pady=(8, 0))
                else:
                    ai_status.config(text=f"Error: {result['message']}", fg=ACCENT)
                    ai_status.pack(pady=(4, 0))

            ai_button = tk.Button(inner, text="Get AI Recommendation for Group",
                                  bg=MATCH_CLR, fg=TEXT,
                                  font=("Georgia", 10, "bold"), relief="flat",
                                  cursor="hand2", pady=8, command=do_ai)
            ai_button.pack(fill="x", padx=24, pady=(12, 0))

        def do_leave():
            """Stops polling, notifies the server, and returns to the lobby."""
            self._room.stop_polling()
            def go():
                try: self._conn.leave_room(self.username, code)
                except Exception: pass
            threading.Thread(target=go, daemon=True).start()
            self._room.leave()
            self._build_party_lobby()

        tk.Button(inner, text="Leave Room", bg=ACCENT, fg=TEXT,
                  font=("Georgia", 11, "bold"), relief="flat",
                  cursor="hand2", pady=8,
                  command=do_leave).pack(fill="x", padx=24, pady=(12, 20))

        def poll():
            """Polls the server every 3 seconds while the room is active."""
            if not self._room.polling: return
            def fetch():
                try:
                    result = self._conn.get_room(code)
                    if self._room.polling:
                        self.after(0, update_ui, result)
                except Exception: pass
            threading.Thread(target=fetch, daemon=True).start()
            self.after(3000, poll)

        def update_ui(result):
            """Updates the member list, picks display, and AI recommendation from poll data."""
            if result["status"] != "ok": return
            members = result.get("members", [])
            host    = result.get("host", "")
            members_lbl.config(
                text="\n".join(f"  {'👑' if m == host else '👤'}  {m}" for m in members))
            picks = result.get("movie_picks", {})
            if picks:
                picks_lbl.config(
                    text="\n".join(f"  {u}: \"{t}\"" for u, t in picks.items()), fg=TEXT)
            else:
                picks_lbl.config(text="  None yet", fg=SUBTEXT)
            ai_rec = result.get("ai_recommendation")
            if ai_rec and not ai_lbl.winfo_ismapped():
                ai_lbl.config(text=ai_rec)
                ai_lbl.pack(fill="x", padx=24, pady=(8, 0))

        poll()

    def _build_stats_tab(self):
        """
        Builds the scrollable skeleton of the Profile tab.
        Creates the Canvas + Scrollbar structure; actual content is populated
        by _refresh_stats every time the tab is opened.
        """
        f = self._stats_frame

        outer = tk.Frame(f, bg=BG)
        outer.pack(fill="both", expand=True)

        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")
        self._profile_canvas = tk.Canvas(outer, bg=BG, highlightthickness=0,
                                         yscrollcommand=sb.set)
        self._profile_canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=self._profile_canvas.yview)

        self._profile_inner = tk.Frame(self._profile_canvas, bg=BG)
        self._profile_cw = self._profile_canvas.create_window(
            (0, 0), window=self._profile_inner, anchor="nw"
        )
        self._profile_inner.bind(
            "<Configure>",
            lambda e: self._profile_canvas.configure(
                scrollregion=self._profile_canvas.bbox("all")
            )
        )
        self._profile_canvas.bind(
            "<Configure>",
            lambda e: self._profile_canvas.itemconfig(self._profile_cw, width=e.width)
        )
        outer.bind(
            "<MouseWheel>",
            lambda e: self._profile_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        )

    def _refresh_stats(self):
        """
        Rebuilds the entire Profile tab content every time the tab is opened.
        Renders: avatar, action buttons, AI taste bio, favourite movies section,
        and stats section. Fetches the bio and stats data in background threads.
        """
        for w in self._profile_inner.winfo_children():
            w.destroy()

        header = tk.Frame(self._profile_inner, bg=BG)
        header.pack(fill="x", padx=24, pady=(24, 0))

        avatar_size = 72
        avatar_canvas = tk.Canvas(header, width=avatar_size, height=avatar_size,
                                  bg=BG, highlightthickness=0)
        avatar_canvas.pack(side="left", padx=(0, 16))
        avatar_canvas.create_oval(2, 2, avatar_size - 2, avatar_size - 2,
                                  fill=STATS_CLR, outline="")
        initials = self.username[0].upper()
        avatar_canvas.create_text(avatar_size // 2, avatar_size // 2,
                                  text=initials, fill=BG, font=("Georgia", 28, "bold"))

        name_block = tk.Frame(header, bg=BG)
        name_block.pack(side="left", fill="y")
        tk.Label(name_block, text=self.username, bg=BG, fg=TEXT,
                 font=("Georgia", 20, "bold"), anchor="w").pack(anchor="w")
        tk.Label(name_block, text="Cinematch member", bg=BG, fg=SUBTEXT,
                 font=("Georgia", 10), anchor="w").pack(anchor="w")

        btn_row = tk.Frame(self._profile_inner, bg=BG)
        btn_row.pack(fill="x", padx=24, pady=(14, 0))
        for label, color, cmd in [
            ("📋  My List",  WATCHED_CLR, self._show_my_list_window),
            ("👥  Friends",  MATCH_CLR,   self._show_friends_window),
        ]:
            tk.Button(btn_row, text=label, bg=color, fg=TEXT,
                      font=("Georgia", 10, "bold"), relief="flat", cursor="hand2",
                      padx=14, pady=8,
                      command=cmd).pack(side="left", expand=True, fill="x", padx=(0, 8))

        tk.Frame(self._profile_inner, bg="#333333", height=1).pack(
            fill="x", padx=24, pady=(18, 16))

        self._bio_frame = tk.Frame(self._profile_inner, bg=CARD_BG,
                                    highlightthickness=1, highlightbackground="#333")
        self._bio_frame.pack(fill="x", padx=24, pady=(14, 0))

        self._bio_lbl = tk.Label(self._bio_frame,
                                  text="✦ Generating your taste profile...",
                                  bg=CARD_BG, fg="#a78bfa",
                                  font=("Georgia", 10, "italic"),
                                  wraplength=340, justify="left",
                                  padx=14, pady=12)
        self._bio_lbl.pack(fill="x")

        def fetch_bio():
            """Fetches the AI taste bio in a background thread and updates the label."""
            bio = self._conn.get_taste_bio()
            if bio:
                self.after(0, lambda: self._bio_lbl.config(text=f"✦  {bio}"))
            else:
                self.after(0, lambda: self._bio_lbl.config(text=""))
                self.after(0, lambda: self._bio_frame.pack_forget())
        threading.Thread(target=fetch_bio, daemon=True).start()

        tk.Frame(self._profile_inner, bg="#333333", height=1).pack(
            fill="x", padx=24, pady=(18, 16))

        tk.Label(self._profile_inner, text="⭐  My Favourite Movies",
                 bg=BG, fg=STATS_CLR, font=("Georgia", 13, "bold"),
                 anchor="w").pack(fill="x", padx=24, pady=(0, 8))

        fav_card = tk.Frame(self._profile_inner, bg=CARD_BG,
                            highlightthickness=1, highlightbackground="#333")
        fav_card.pack(fill="x", padx=24, pady=(0, 4))

        tk.Label(fav_card,
                 text="The three movies that define your taste — used by the AI to personalise recommendations.",
                 bg=CARD_BG, fg=SUBTEXT, font=("Georgia", 9),
                 wraplength=340, justify="left").pack(anchor="w", padx=14, pady=(10, 6))

        self._fav_entries = []
        for i in range(1, 4):
            row = tk.Frame(fav_card, bg=CARD_BG)
            row.pack(fill="x", padx=14, pady=(0, 8))
            tk.Label(row, text=f"#{i}", bg=CARD_BG, fg=STATS_CLR,
                     font=("Georgia", 11, "bold"), width=3).pack(side="left")
            entry = tk.Entry(row, bg=INPUT_BG, fg=TEXT, insertbackground=TEXT,
                             relief="flat", font=("Georgia", 11))
            entry.pack(side="left", expand=True, fill="x", ipady=7, padx=(4, 0))
            self._fav_entries.append(entry)

        save_row = tk.Frame(fav_card, bg=CARD_BG)
        save_row.pack(fill="x", padx=14, pady=(0, 12))
        self._fav_status = tk.Label(save_row, text="", bg=CARD_BG,
                                    fg=WANT_CLR, font=("Georgia", 9))
        self._fav_status.pack(side="left")
        tk.Button(save_row, text="Save", bg=STATS_CLR, fg=BG,
                  font=("Georgia", 10, "bold"), relief="flat", cursor="hand2",
                  padx=14, pady=5,
                  command=self._save_favorites).pack(side="right")

        tk.Frame(self._profile_inner, bg="#333333", height=1).pack(
            fill="x", padx=24, pady=(10, 16))

        tk.Label(self._profile_inner, text="📊  My Stats",
                 bg=BG, fg=STATS_CLR, font=("Georgia", 13, "bold"),
                 anchor="w").pack(fill="x", padx=24, pady=(0, 8))

        self._stats_content = tk.Frame(self._profile_inner, bg=BG)
        self._stats_content.pack(fill="x", padx=24, pady=(0, 24))

        self._stats_loading = tk.Label(self._stats_content, text="Loading stats...",
                                       bg=BG, fg=SUBTEXT, font=("Georgia", 11))
        self._stats_loading.pack(pady=12)

        def fetch():
            """Fetches favourite movies and stats in one background thread."""
            try:
                favs  = self._conn.get_favorite_movies()
                stats = self._conn.get_stats(self.username)
                self.after(0, self._populate_profile, favs, stats)
            except Exception as e:
                self.after(0, lambda: self._stats_loading.config(
                    text=f"Error loading profile: {e}", fg=ACCENT))
        threading.Thread(target=fetch, daemon=True).start()

    def _populate_profile(self, favs: list, stats: dict):
        """
        Fills the favourite-movie entry fields with saved titles and renders
        the statistics rows once the background fetch has completed.
        """
        for i, entry in enumerate(self._fav_entries):
            entry.delete(0, "end")
            if i < len(favs) and favs[i]:
                entry.insert(0, favs[i])

        self._stats_loading.pack_forget()
        for w in self._stats_content.winfo_children():
            w.destroy()

        if stats.get("status") != "ok":
            tk.Label(self._stats_content, text="Could not load stats",
                     bg=BG, fg=ACCENT, font=("Georgia", 11)).pack(pady=12)
            return

        rows = [
            ("🎬  Total movies seen",      str(stats["total"])),
            ("✅  Already watched",         str(stats["watched_count"])),
            ("👀  Want to watch",           str(stats["want_count"])),
            ("❌  Don't want",              str(stats["dont_count"])),
            ("⭐  Average personal rating", f"{stats['avg_rating']}/10  ({stats['rated_count']} rated)"),
            ("🎭  Favourite genre",         stats["fav_genre"]),
            ("📅  Favourite decade",        stats["fav_decade"]),
            ("👥  Best match friend",       f"{stats['best_friend']}  ({stats['best_compat']}%)"),
        ]
        for label, value in rows:
            row = tk.Frame(self._stats_content, bg=CARD_BG,
                           highlightthickness=1, highlightbackground="#333")
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg=CARD_BG, fg=SUBTEXT,
                     font=("Georgia", 10), anchor="w", padx=14, pady=10).pack(side="left")
            tk.Label(row, text=value, bg=CARD_BG, fg=TEXT,
                     font=("Georgia", 11, "bold"), anchor="e", padx=14).pack(side="right")

    def _save_favorites(self):
        """
        Reads the three favourite-movie entry fields and sends them to the server.
        Displays a confirmation message for 3 seconds, then clears it.
        """
        titles = [e.get().strip() for e in self._fav_entries]
        def go():
            result = self._conn.save_favorite_movies(titles)
            color  = WANT_CLR if result.get("status") == "ok" else ACCENT
            msg    = "Saved!" if result.get("status") == "ok" else result.get("message", "Error")
            self.after(0, lambda: self._fav_status.config(text=msg, fg=color))
            self.after(3000, lambda: self._fav_status.config(text=""))
        threading.Thread(target=go, daemon=True).start()

    def _build_search_tab(self):
        """
        Builds the Search tab UI: a text entry with a Search button (and Enter-key binding),
        a status label, and a results area that is populated by _render_search_results.
        """
        f = self._search_frame
        tk.Label(f, text="Search Movies", bg=BG, fg=SEARCH_CLR,
                 font=("Georgia", 18, "bold")).pack(pady=(20, 12))

        bar = tk.Frame(f, bg=BG)
        bar.pack(fill="x", padx=20, pady=(0, 8))
        self._search_entry = tk.Entry(bar, bg=INPUT_BG, fg=TEXT,
                                      insertbackground=TEXT, relief="flat",
                                      font=("Georgia", 12))
        self._search_entry.pack(side="left", expand=True, fill="x", ipady=9, padx=(0, 8))
        self._search_entry.bind("<Return>", lambda e: self._do_search())
        tk.Button(bar, text="Search", bg=SEARCH_CLR, fg=TEXT,
                  font=("Georgia", 11, "bold"), relief="flat", cursor="hand2",
                  padx=12, pady=9,
                  command=self._do_search).pack(side="right")

        self._search_status = tk.Label(f, text="Type a movie name and press Search",
                                       bg=BG, fg=SUBTEXT, font=("Georgia", 10))
        self._search_status.pack(pady=(0, 8))

        self._search_results_frame = tk.Frame(f, bg=BG)
        self._search_results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

    def _do_search(self):
        """
        Reads the search query, clears previous results, shows a loading status,
        then fetches results from the server in a background thread.
        """
        query = self._search_entry.get().strip()
        if not query: return
        self._search_status.config(text="Searching...")
        for w in self._search_results_frame.winfo_children(): w.destroy()
        def fetch():
            results = self._conn.search_movies(query)
            self.after(0, self._render_search_results, results)
        threading.Thread(target=fetch, daemon=True).start()

    def _render_search_results(self, results: list):
        """
        Renders the search results as a scrollable clickable list.
        Each row shows title, year, and TMDB rating. Clicking any row opens _show_movie_detail.
        """
        self._search_status.config(
            text=f"{len(results)} results found" if results else "No results found")
        if not results: return

        outer = tk.Frame(self._search_results_frame, bg=BG)
        outer.pack(fill="both", expand=True)
        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")

        for movie in results:
            row = tk.Frame(inner, bg=CARD_BG,
                           highlightthickness=1, highlightbackground="#333",
                           cursor="hand2")
            row.pack(fill="x", pady=4, padx=2)
            left = tk.Frame(row, bg=CARD_BG, cursor="hand2")
            left.pack(fill="both", expand=True, padx=12, pady=10)

            title = movie.get("title", "Unknown")
            year  = str(movie.get("release_date", ""))[:4]
            avg   = movie.get("vote_average", 0)

            lbl_t = tk.Label(left, text=title, bg=CARD_BG, fg=TEXT,
                             font=("Georgia", 11, "bold"),
                             anchor="w", wraplength=340, cursor="hand2")
            lbl_t.pack(fill="x")
            lbl_m = tk.Label(left, text=f"{year}  |  ⭐ {avg:.1f}/10",
                             bg=CARD_BG, fg=SUBTEXT, font=("Georgia", 9),
                             anchor="w", cursor="hand2")
            lbl_m.pack(fill="x")

            for widget in (row, left, lbl_t, lbl_m):
                widget.bind("<Button-1>", lambda e, m=movie: self._show_movie_detail(m))

        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        outer.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

    def _show_movie_detail(self, movie: dict):
        """
        Opens a detail window for a movie selected from search results.
        Downloads the poster in a background thread and presents Want / Watched / Skip buttons
        that save the choice to both MovieLibrary and the server.
        """
        win = tk.Toplevel(self)
        win.title(movie.get("title", "Movie"))
        win.configure(bg=BG)
        win.geometry("400x640")
        win.resizable(False, False)

        outer = tk.Frame(win, bg=BG)
        outer.pack(fill="both", expand=True)
        sb = tk.Scrollbar(outer, bg=CARD_BG, troughcolor=BG, highlightthickness=0)
        sb.pack(side="right", fill="y")
        canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.config(command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        cw = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(cw, width=e.width))
        outer.bind("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        poster_lbl = tk.Label(inner, bg=BG, text="Loading poster...", fg=SUBTEXT,
                              font=("Georgia", 10))
        poster_lbl.pack(pady=(16, 0))

        def load_img():
            """Downloads and displays the poster; shows a placeholder on failure."""
            path = movie.get("poster_path", "")
            if path:
                photo = load_poster(path, size=(260, 370))
                if photo:
                    win.after(0, lambda: [poster_lbl.config(image=photo, text="", bg=BG),
                                          setattr(poster_lbl, "_photo", photo)])
                    return
            win.after(0, lambda: poster_lbl.config(text="[No poster]", fg=SUBTEXT))
        threading.Thread(target=load_img, daemon=True).start()

        tk.Label(inner, text=movie.get("title", "Unknown"), bg=BG, fg=TEXT,
                 font=("Georgia", 16, "bold"), wraplength=360,
                 justify="center").pack(padx=16, pady=(14, 0))

        year  = str(movie.get("release_date", ""))[:4]
        avg   = movie.get("vote_average", 0)
        votes = movie.get("vote_count", 0)
        tk.Label(inner, text=f"{year}  |  ⭐ {avg:.1f}/10  ({votes:,} votes)",
                 bg=BG, fg=SUBTEXT, font=("Georgia", 10)).pack(pady=(4, 0))

        tk.Label(inner, text=movie.get("overview", "No description available."),
                 bg=BG, fg=SUBTEXT, font=("Georgia", 10),
                 wraplength=360, justify="left").pack(padx=20, pady=(12, 16))

        status_lbl = tk.Label(inner, text="", bg=BG, fg=WANT_CLR,
                              font=("Georgia", 10, "bold"))
        status_lbl.pack(pady=(0, 8))

        def save_status(status, rating=None):
            """Updates the local library, saves to server, and shows a confirmation label."""
            self._library.add(movie, status, rating)
            self._update_score()
            data = self._library.movie_data_from(movie)
            threading.Thread(target=self._conn.save_movie,
                             args=(self.username, data, status, rating),
                             daemon=True).start()
            labels = {
                "want_to_watch":   "Added to Want to Watch ✓",
                "dont_want":       "Added to Don't Want ✓",
                "already_watched": f"Saved as Watched (rating: {rating}/10) ✓",
            }
            status_lbl.config(text=labels.get(status, "Saved ✓"), fg=WANT_CLR)

        def on_watched():
            """Opens the rating popup before saving as already-watched."""
            show_rating_popup(win, lambda r: save_status("already_watched", r))

        btn_frame = tk.Frame(inner, bg=BG)
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))

        tk.Button(btn_frame, text="Want to Watch", bg=WANT_CLR, fg=TEXT,
                  font=("Georgia", 10, "bold"), relief="flat", cursor="hand2", pady=10,
                  command=lambda: save_status("want_to_watch")
                  ).pack(fill="x", pady=(0, 6))
        tk.Button(btn_frame, text="Already Watched", bg=WATCHED_CLR, fg=TEXT,
                  font=("Georgia", 10, "bold"), relief="flat", cursor="hand2", pady=10,
                  command=on_watched).pack(fill="x", pady=(0, 6))
        tk.Button(btn_frame, text="Don't Want", bg=DONT_CLR, fg=TEXT,
                  font=("Georgia", 10, "bold"), relief="flat", cursor="hand2", pady=10,
                  command=lambda: save_status("dont_want")
                  ).pack(fill="x")

    def _on_close(self):
        """
        Handles the window close event:
        stops polling, leaves the Watch Party room if active, closes the socket,
        and destroys the window.
        """
        self._room.stop_polling()
        if self._room.is_active:
            try: self._conn.leave_room(self.username, self._room.code)
            except Exception: pass
        self._conn.close()
        self.destroy()


# ─── Entry point ──────────────────────────────────────

if __name__ == "__main__":
    auth = AuthWindow()
    auth.mainloop()

    if auth.username and auth.conn:
        app = MovieGameApp(conn=auth.conn, username=auth.username)
        app.mainloop()