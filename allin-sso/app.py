"""This is the single sign-on app"""

import os
import flask
from flask_oauthlib.client import OAuth

SECRET_KEY = os.getenv('SECRET_KEY')
DISCORD_CLIENT_KEY = os.getenv("DISCORD_CLIENT_KEY")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")

OAUTH = OAuth()
DISCORD = OAUTH.remote_app(
    'discord',
    base_url='https://discordapp.com/api',
    access_token_url='https://discordapp.com/api/oauth2/token',
    authorize_url='https://discordapp.com/api/oauth2/authorize',
    request_token_url=None,
    consumer_key=DISCORD_CLIENT_KEY,
    consumer_secret=DISCORD_CLIENT_SECRET,
    request_token_params={'scope': 'identify'})

APP = flask.Flask(__name__, template_folder='templates/')
APP.secret_key = SECRET_KEY

@DISCORD.tokengetter
def get_discord_token(token=None):
    return flask.session.get('discord_token')

@APP.route('/static/<path:path>')
def static_files():
    """Endpoint for serving static files"""
    return flask.send_from_directory('static', path)

@APP.route('/')
def index():
    """This is the main landing page for the app"""
    return flask.render_template('index.html.j2')

@APP.route('/discord-login')
def discord_login():
    """This is the endpoint for commencing authorisation using discord"""
    return DISCORD.authorize(callback='http://localhost:5000/discord-authorised')

@APP.route('/discord-authorised')
def discord_authorised():
    """This is the endpoint for the oauth2 callback for discord"""
    resp = DISCORD.authorized_response()
    if resp is None:
        return flask.redirect('/')

    flask.session['discord_token'] = (resp['oauth_token'], resp['oauth_token_secret'])
    print(flask.session['discord_token'])
    return flask.redirect('/usersettings/')

@APP.route('/usersettings/')
def user_settings():
    """This is the main user landing page after they have authenticated."""
    resp = DISCORD.get('/users/@me', token=flask.session['discord_token'])
    if resp.status == 200:
        print(resp.data["name"])

    return flask.redirect('/')
