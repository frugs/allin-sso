import flask
import flask_oauthlib.client


def create_discord_remote_app(
        oauth: flask_oauthlib.client.OAuth,
        discord_client_key: str,
        discord_client_secret: str,
) -> flask_oauthlib.client.OAuthRemoteApp:

    return oauth.remote_app(
        "discord",
        consumer_key=discord_client_key,
        consumer_secret=discord_client_secret,
        request_token_params={"scope": "identify connections"},
        base_url="https://discordapp.com/api/v6/",
        request_token_url=None,
        access_token_method='POST',
        access_token_url="https://discordapp.com/api/oauth2/token",
        authorize_url="https://discordapp.com/api/oauth2/authorize",
        access_token_headers={
            "User-Agent": "Mozilla/5.0"
        })


def refresh_discord_token(discord: flask_oauthlib.client.OAuthRemoteApp, session) -> str:
    resp = discord.post(
        discord.access_token_url,
        token="token",
        headers={"User-Agent": "Mozilla/5.0"},
        data={
            "grant_type": "refresh_token",
            "client_id": discord.consumer_key,
            "client_secret": discord.consumer_secret,
            "refresh_token": session.get("discord_refresh_token", ""),
        })

    if resp.status == 200:
        access_token = resp.data.get("access_token", "")
        refresh_token = resp.data.get("refresh_token", "")
    else:
        access_token = ""
        refresh_token = ""

    if refresh_token:
        session["discord_refresh_token"] = refresh_token

    return access_token
