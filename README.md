# AIOStremio

AIOStremio combines your favorite Stremio addons into one. Easily sync your setup with friends—changes update for all users without any reconfiguration on their end. [Discord Server](https://discord.gg/dU7KcppT6M)

(Note: Not all services allow account sharing, and it may lead to a ban. Consider using [TorBox](https://torbox.app/subscription?referral=fe897519-fa8d-402d-bdb6-15570c60eff2) (referral link), which allows account sharing.)

![Stremio on Android TV](https://i.postimg.cc/YthHbCzs/PNG-image.png)

## Features
- Account system
- Fetch links from multiple addons
- Manually fetch and cache all links for a specific title using `python3 build_cache.py [--series|--movie] [IMDb ID]` (do not abuse this or you will likely get IP banned from the upstream addons)
- Optional encryption of video URLs and proxy streams to bypass IP restrictions on debrid services (at your own risk) and avoid exposing your API keys/passwords
- Redis cache that instantly returns links already fetched by other users
- Very easy to add support for new addons

## Supported Stremio Addons
- Torrentio
- Comet
- MediaFusion
- TorBox
- Easynews
- Debridio

## Future Addon Support
- Easynews+ (exposes user+password in authorization headers)

## Setup
Requirements:
- Docker
- Reverse proxy (https://caddyserver.com/docs/quick-starts/reverse-proxy)

1. Clone the repo: `git clone https://github.com/stekc/AIOStremio`
2. Copy and rename .env.example to .env and fill out the required fields:

Create an admin account that will be used to add new users and toggle proxy streams:
```
ADMIN_USERNAME=
ADMIN_PASSWORD=
```
If you are not proxying streams or using MediaFlow, this can be left blank. If using the built-in proxy, run `python3 gen_key.py` and add the key:
```
ENCRYPTION_KEY=
```
If you are proxying streams with MediaFlow, generate a secure password to prevent unauthorized access:
```
MEDIAFLOW_API_KEY=
```
When set to true, MediaFlow will log detailed proxied stream info:
```
MEDIAFLOW_STREAMING_PROGRESS=true
```
Your Real-Debrid/Premiumize/TorBox/etc. API key. If you are only using EasyNews, this can be left blank:
```
DEBRID_API_KEY=
```
Generate a MediaFusion manifest at https://mediafusion.elfhosted.com/, then copy the string of random characters between `https://mediafusion.elfhosted.com/` and `/manifest.json`. If you do not want to use MediaFusion, leave this field blank:
```
MEDIAFUSION_OPTIONS=
```
Your EasyNews username and password. If you are only using a debrid service, this can be left blank:
```
EASYNEWS_USERNAME=
EASYNEWS_PASSWORD=
```
Generate a secure password for the Redis cache. Host and port should be left as default when using Docker:
```
REDIS_HOST=debridproxy_redis
REDIS_PORT=6379
REDIS_PASSWORD=
```

3. Copy and rename config.json.example to config.json and fill out the required fields:

If using a debrid service, specify it here:
```
"debrid_service": "torbox",
```
If you want to use different debrid services for different addons, specify them here, otherwise leave blank:
```
"addon_config": {
    "torrentio": {
        "debrid_service": "",
        "debrid_api_key": ""
    },
    "comet": {
        "debrid_service": "",
        "debrid_api_key": ""
    },
    "debridio": {
        "debrid_service": "easydebrid",
        "debrid_api_key": ""
    }
},
```
The domain where the addon will be accessible:
```
"addon_url": "https://debridproxy.your-domain.com",
```
The domain used when generating links, leave as default unless using another instance (ElfHosted, etc.):
```
"mediaflow_url": "http://debridproxy_mediaflow:8888",
```
The domain returned in the generated links, leave as default unless using another instance:
```
"external_mediaflow_url": "https://mediaflow.your-domain.com",
```
When disabled, the addon will use the built-in proxy streaming. Unless you experience issues with MediaFlow, leave this set to true:
```
"mediaflow_enabled": true,
```
How long in seconds fetched links will be cached:
```
"cache_ttl_seconds": 604800,
```
Advanced built-in proxy options. Does not affect MediaFlow. Leave this as default unless the built-in proxy has issues:
```
"buffer_size_mb": 256,
"chunk_size_mb": 4,
```
Vidi does not show titles such as "Torrentio [RD+] 4k", so when set to true, these will be added to the description. Leave this set to false if you're using Stremio:
```
"vidi_mode": false
```

3. Configure your reverse proxy. If you are using Caddy in Docker, this Caddyfile should work:
```
aiostremio.your-domain.com {
    reverse_proxy debridproxy:8469
}
 
mediaflow.your-domain.com {
    reverse_proxy debridproxy_mediaflow:8888
}
```

4. Run `docker compose up -d` to start the addon.

5. Navigate to aiostremio.your-domain.com/admin to add a user.

6. Navigate to aiostremio.your-domain.com/ to generate a manifest.

7. Add the generated URL to Stremio/Vidi/etc. and start watching.

## Credits
Torrentio, Comet, MediaFusion, and all other upstream addons - Used for fetching links

[MediaFlow](https://github.com/mhdzumair/mediaflow-proxy) - Used for proxy streams

## Notes
- MediaFlow is recommended for video proxying, though you can use the internal proxy by editing the config if you have issues.
- AIOStremio is primarily tested with TorBox. Please open an issue if other debrid services do not work.
