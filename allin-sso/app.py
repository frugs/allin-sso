"""This is the single sign-on app"""

import os
import aiohttp
import aiohttp.web
import aiohttp_jinja2
import jinja2
import aioauth_client
import aiohttp_session

from typing import Union
from aiohttp_session.cookie_storage import EncryptedCookieStorage

SECRET_KEY = os.getenv('SECRET_KEY')
DISCORD_CLIENT_KEY = os.getenv("DISCORD_CLIENT_KEY")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_CALLBACK_URL = os.getenv("DISCORD_CALLBACK_URL")
DEFAULT_REDIRECT_PATH = os.getenv("DEFAULT_REDIRECT_PATH")


DISCORD = aioauth_client.OAuth2Client(
    DISCORD_CLIENT_KEY,
    DISCORD_CLIENT_SECRET,
    base_url='https://discordapp.com/api/v6/',
    access_token_url='https://discordapp.com/api/oauth2/token',
    authorize_url='https://discordapp.com/api/oauth2/authorize')


def discord_auth_headers(access_token: str) -> dict:
    return {'Authorization': "Bearer " + access_token}


async def do_discord_refresh_token(refresh_token: str) -> dict:
    resp = await DISCORD.request(
        "POST",
        DISCORD.access_token_url,
        data={
            'grant_type': 'refresh_token',
            'client_id': DISCORD.client_id,
            'client_secret': DISCORD.client_secret,
            'refresh_token': refresh_token,
        }
    )

    if resp.status == 200:
        return await resp.json()
    else:
        return {}


async def root(_: aiohttp.web.Request) -> aiohttp.web.Response:
    return aiohttp.web.HTTPMovedPermanently('index')


@aiohttp_jinja2.template('index.html.j2')
async def index(request: aiohttp.web.Request) -> Union[dict, aiohttp.web.Response]:
    """This is the main landing page for the app"""
    session = await aiohttp_session.get_session(request)
    resp = await do_discord_refresh_token(session.get("discord_refresh_token", ""))
    if resp:
        return aiohttp.web.HTTPFound(DEFAULT_REDIRECT_PATH)
    else:
        return {}


async def discord_login(_: aiohttp.web.Request) -> aiohttp.web.Response:
    """This is the endpoint for commencing authorisation using discord"""
    params = {
        'scope': 'identify',
        'response_type': 'code',
        'redirect_uri': DISCORD_CALLBACK_URL
    }
    return aiohttp.web.HTTPFound(DISCORD.get_authorize_url(**params))


async def discord_signout(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Clears access token from session"""
    session = await aiohttp_session.get_session(request)
    session.pop('discord_refresh_token', None)
    return aiohttp.web.HTTPFound('index')


async def discord_authorised(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """This is the endpoint for the oauth2 callback for discord"""
    code = request.rel_url.query.get('code')
    if code is None:
        return aiohttp.web.HTTPFound('index')

    access_token, data = await DISCORD.get_access_token(code, redirect_uri=DISCORD_CALLBACK_URL)

    session = await aiohttp_session.get_session(request)
    session['discord_refresh_token'] = data['refresh_token']

    return aiohttp.web.HTTPFound(DEFAULT_REDIRECT_PATH)


async def discord_refresh_token(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Endpoint for refreshing discord access token"""
    data = await request.json()
    refresh_token_data = await do_discord_refresh_token(data.get("discord_refresh_token", ""))

    if refresh_token_data:
        return aiohttp.web.json_response(refresh_token_data)
    else:
        return aiohttp.web.HTTPForbidden(reason="Invalid refresh token")


def main():
    app = aiohttp.web.Application()
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('templates/'))
    aiohttp_session.setup(app, EncryptedCookieStorage(SECRET_KEY, max_age=604800))

    app.router.add_static('/static/', 'static/')
    app.router.add_get('/', root)
    app.router.add_get('/index', index)
    app.router.add_get('/discord-login', discord_login)
    app.router.add_get('/discord-signout', discord_signout)
    app.router.add_get('/discord-authorised', discord_authorised)
    app.router.add_post('/discord-refresh-token', discord_refresh_token)

    aiohttp.web.run_app(app, port=5000)


if __name__ == "__main__":
    main()
