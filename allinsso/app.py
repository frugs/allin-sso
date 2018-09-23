"""This is the single sign-on app"""
from typing import Tuple

import flask
import flask_oauthlib.client

from google.cloud import datastore


def retrieve_config_value(key: str) -> str:
    datastore_client = datastore.Client()
    return datastore_client.get(datastore_client.key("Config", key))["value"]


SECRET_KEY = retrieve_config_value("cookieEncryptionKey")
DISCORD_CLIENT_KEY = retrieve_config_value("discordClientKey")
DISCORD_CLIENT_SECRET = retrieve_config_value("discordClientSecret")
POST_LOGIN_REDIRECT_PATH = "/usersettings/"

app = flask.Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = flask_oauthlib.client.OAuth(app)

discord = oauth.remote_app(
    "discord",
    consumer_key=DISCORD_CLIENT_KEY,
    consumer_secret=DISCORD_CLIENT_SECRET,
    request_token_params={"scope": "identify connections"},
    base_url="https://discordapp.com/api/v6/",
    request_token_url=None,
    access_token_method='POST',
    access_token_url="https://discordapp.com/api/oauth2/token",
    authorize_url="https://discordapp.com/api/oauth2/authorize",
    access_token_headers={
        "User-Agent": "Mozilla/5.0"
    })


def discord_auth_headers(access_token: str) -> dict:
    return {"Authorization": "Bearer " + access_token}


def do_discord_refresh_token(refresh_token: str) -> Tuple[str, str]:
    resp = discord.post(
        discord.access_token_url,
        token="token",
        headers={"User-Agent": "Mozilla/5.0"},
        data={
            "grant_type": "refresh_token",
            "client_id": discord.consumer_key,
            "client_secret": discord.consumer_secret,
            "refresh_token": refresh_token,
        })

    if resp.status == 200:
        return resp.data.get("access_token", ""), resp.data.get("refresh_token", "")
    else:
        return "", ""


@app.route("/")
def index():
    """This is the main landing page for the app"""

    access_token, refresh_token = do_discord_refresh_token(
        flask.session.get("discord_refresh_token", ""))

    if refresh_token:
        flask.session["discord_refresh_token"] = refresh_token

    if access_token:
        return flask.redirect(POST_LOGIN_REDIRECT_PATH)
    else:
        return flask.render_template("index.html.j2")


@app.route("/discord-login")
def discord_login():
    """This is the endpoint for commencing authorisation using discord"""

    return discord.authorize(
        callback=flask.url_for(
            discord_authorised.__name__, _external=True, _scheme=flask.request.scheme))


@app.route("/discord-signout")
def discord_signout():
    """Clears access token from session"""

    flask.session.pop('discord_refresh_token', None)
    return flask.redirect(flask.url_for(index.__name__))


@app.route("/discord-authorised")
def discord_authorised():
    """This is the endpoint for the oauth2 callback for discord"""

    resp = discord.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return "Login failed", 401

    flask.session["discord_access_token"] = resp["access_token"]
    flask.session["discord_refresh_token"] = resp["refresh_token"]

    return flask.redirect(POST_LOGIN_REDIRECT_PATH)


@app.route("/discord-refresh-token", methods=["POST"])
def discord_refresh_token():
    """Endpoint for refreshing discord access token"""

    if not flask.request.is_json:
        return "Bad request", 400

    access_token, refresh_token = do_discord_refresh_token(
        flask.request.json.get("discord_refresh_token", ""))

    return flask.jsonify({
        "discord_access_token": access_token,
        "discord_refresh_token": refresh_token
    })
