from dotenv import load_dotenv
from flask_dance.contrib.google import make_google_blueprint, google

load_dotenv()
client_id = os.getenv("GOOGLE_CLIENT_ID")
client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
secret_key = os.getenv("SECRET_KEY")
blue_print = make_google_blueprint(client_id=client_id,
                                   client_secret=client_secret,
                                   reprompt_consent=True,
                                   scope=["profile", "email"],
                                   )

app.register_blueprint(blue_print)

@app.route("/")
def index():
    google_data = None
    user_info_endpoint = "/oauth2/v2/userinfo"
    if google.authorized:
        google_data = google.get(user_info_endpoint).json()

    return render_template("index.j2", google_data=google_data, fetch_url=google.base_url + user_info_endpoint)


@app.route("/login")
def login():
    return redirect(url_for("google.login"))