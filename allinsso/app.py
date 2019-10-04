"""This is the single sign-on app"""

import secrets
import flask
import flask_oauthlib.client
from google.cloud import datastore

from .discordoauth import refresh_discord_token, create_discord_remote_app

datastore_client = datastore.Client()


def retrieve_config_value(key: str) -> str:
    return datastore_client.get(datastore_client.key("Config", key))["value"]


SECRET_KEY = retrieve_config_value("cookieEncryptionKey")
DISCORD_CLIENT_KEY = retrieve_config_value("discordClientKey")
DISCORD_CLIENT_SECRET = retrieve_config_value("discordClientSecret")
POST_LOGIN_REDIRECT_PATH = "/usersettings/"

app = flask.Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = flask_oauthlib.client.OAuth(app)

discord = create_discord_remote_app(oauth, DISCORD_CLIENT_KEY, DISCORD_CLIENT_SECRET)


def discord_auth_headers(access_token: str) -> dict:
    return {"Authorization": "Bearer " + access_token}


@app.route("/")
def index():
    """This is the main landing page for the app"""

    if refresh_discord_token(discord, flask.session):
        return flask.redirect(POST_LOGIN_REDIRECT_PATH)
    else:
        return flask.render_template("index.html.j2")


@app.route("/discord-login")
def discord_login():
    """This is the endpoint for commencing authorisation using discord"""
    state_key = secrets.token_urlsafe(32)
    redirect_url = flask.request.args.get("redirect_url")
    if redirect_url:
        flask.session[state_key] = {"redirect_url": redirect_url}

    return discord.authorize(
        callback=flask.url_for(
            discord_authorised.__name__, _external=True, _scheme="https"
        ),
        state=state_key
    )


@app.route("/discord-signout")
def discord_signout():
    """Clears access token from session"""

    flask.session.pop("discord_refresh_token", None)
    return flask.redirect(flask.url_for(index.__name__))


@app.route("/discord-authorised")
def discord_authorised():
    """This is the endpoint for the oauth2 callback for discord"""

    resp = discord.authorized_response()
    if resp is None or resp.get("access_token") is None:
        return "Login failed", 401

    flask.session["discord_access_token"] = resp["access_token"]
    flask.session["discord_refresh_token"] = resp["refresh_token"]

    state_key = flask.request.args.get("state")
    state = flask.session.pop(state_key, {})
    redirect_url = state.get("redirect_url", POST_LOGIN_REDIRECT_PATH)
    return flask.redirect(redirect_url)
