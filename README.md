# AIOStremio

AIOStremio combines your favorite Stremio addons into one. Easily sync your setup with friends—changes update for all users without any reconfiguration on their end.

(Note: Not all services allow account sharing, and it may lead to a ban. Consider using [TorBox](https://torbox.app/subscription?referral=fe897519-fa8d-402d-bdb6-15570c60eff2) (referral link), which allows account sharing.)

![Vidi](https://i.postimg.cc/6QKSFn0f/IMG-3704.jpg)

## Features:
- Account system
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
- The majority of testing is done using Vidi and TorBox. Open an issue if something isn't working in Stremio or with other debrid services.
- Stream proxying is an experimental feature. It may take multiple attempts before the stream starts. More testing is needed to ensure no keys are exposed. Do not share this addon with people you wouldn't trust with your API keys.
