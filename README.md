# AIOStremio

AIOStremio combines your favorite Stremio addons into one. Easily sync your setup with friends—changes update for all users without any reconfiguration on their end.

(Note: Not all services allow account sharing, and it may lead to a ban. Consider using [TorBox](https://torbox.app/subscription?referral=fe897519-fa8d-402d-bdb6-15570c60eff2) (referral link), which allows account sharing.)

![Stremio on Android TV](https://i.postimg.cc/YthHbCzs/PNG-image.png)

## Features:
- Account system
- Fetch links from multiple addons
- Optional encryption of video URLs and proxy streams to bypass IP restrictions on debrid services (at your own risk) and avoid exposing your API keys/passwords
- Redis cache that instantly returns links already fetched by other users
- Very easy to add support for new addons

## Supported Stremio addons:
- Torrentio
- Comet
- MediaFusion
- TorBox
- Easynews

## Notes
- MediaFlow is recommended for video proxying, though you can use the internal proxy by editing the config if you have issues.
- AIOStremio is primarily tested with TorBox. Please open an issue if other debrid services do not work.
