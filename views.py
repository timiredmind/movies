import google_auth_oauthlib.flow
import google.oauth2.credentials
from models import User, Base, engine, Movie
from flask import Flask, request, abort, jsonify, g, render_template, url_for, redirect
from sqlalchemy.orm import sessionmaker
from flask_httpauth import HTTPBasicAuth
import os, redis


app = Flask(__name__)
app.secret_key = os.urandom(16)
auth = HTTPBasicAuth()

Base.metadata.bind = engine
Session = sessionmaker(bind=engine)
session = Session()


# Use the client_secret.json file to identify the application requesting
# authorization. The client ID (from that file) and access scopes are required.
flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    'secret.json',
    scopes=['https://www.googleapis.com/auth/drive.metadata.readonly'])

# Indicate where the API server will redirect the user after the user completes
# the authorization flow. The redirect URI is required. The value must exactly
# match one of the authorized redirect URIs for the OAuth 2.0 client, which you
# configured in the API Console. If this value doesn't match an authorized URI,
# you will get a 'redirect_uri_mismatch' error.
flow.redirect_uri = 'https://localhost:5000'

# Generate URL for request to Google's OAuth 2.0 server.
# Use kwargs to set optional request parameters.
authorization_url, state = flow.authorization_url(
    # Enable offline access so that you can refresh an access token without
    # re-prompting the user for permission. Recommended for web server apps.
    access_type='offline',
    # Enable incremental authorization. Recommended as a best practice.
    include_granted_scopes='true',
    prompt="consent")

# @app.route("/")
# def index():


@app.route("/login")
def login():
    return redirect(authorization_url)


@auth.verify_password
def verify_password(username_or_token, password):
    user_id = User.verify_auth_token(username_or_token)
    if not user_id:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    else:
        user = session.query(User).filter_by(id=user_id).one()
    g.user = user
    return True


@app.route("/users", methods=["POST"])
def create_users():
    json_data = request.get_json()
    if json_data is None:
        abort(400, "Username and Password missing")
    username = json_data.get("username")
    password = json_data.get("password")
    if username is None:
        abort(422, "Username is missing")

    if password is None:
        abort(422, "Password is missing")

    if session.query(User).filter_by(username=username).first() is not None:
        abort(400, "Username already exists")

    user = User(username=username)
    user.hash_password(str(password))
    session.add(user)
    session.commit()
    return jsonify({"username": username}), 201


@app.route("/movies", methods=["POST", "GET"])
@auth.login_required
def list_of_movies():
    if request.method == "GET":
        movies = session.query(Movie).all()
        return jsonify([{"id": movie.id, "title": movie.title}
                        for movie in movies])

    if request.method == "POST":
        json_data = request.json
        if not json_data or len(json_data) != 1:
            abort(400)
        if json_data.get("rating"):
            rating = json_data.get("rating")
            movies = session.query(Movie).filter_by(rating=float(rating)).all()
            return jsonify([movie.serialize for movie in movies])

        elif json_data.get("year_of_release"):
            year = json_data.get("year_of_release")
            movies = session.query(Movie).filter(
                Movie.year_of_release >= year).all()
            return jsonify([movie.serialize for movie in movies])


@app.route("/movies/<int:id>")
@auth.login_required
def return_movies(id):
    movie = session.query(Movie).filter_by(id=id).first()
    if not movie:
        return jsonify({})
    return jsonify(movie.serialize)


@app.route("/api/token")
@auth.login_required
def get_auth_token():
    duration = 600
    token = g.user.generate_auth_token(duration)
    return jsonify(
        {
            "token": token.decode("ascii"),
            "duration": duration,
            "message": f"After {duration} secs, request for a new token"
        }
    )


@app.route("/details")
@auth.login_required
def get_username():
    return jsonify({"username": g.user.username})


if __name__ == "__main__":
    app.config["SESSION_TYPE"] = "filesystem"
    app.run(debug=True)


# print(client_id)
# print(client_secret_key)
