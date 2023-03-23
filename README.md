<!--
 Copyright (c) 2023 weooh

 This software is released under the MIT License.
 https://opensource.org/licenses/MIT
-->

# Transmission IP Block list

屏蔽迅雷等吸血鬼客户端IP

## Usage

### 1. transmission client

1. Open `Edit` -> `Preferences`
2. Switch to `Privacy` tab
3. on `Blocklist`-> `Enable blocklist`, paste `block.txt` file path to the field
   e.g. [public block file](https://raw.githubusercontent.com/FriesI23/transmission-block-list/master/block.txt)

### 2. transmission daemon

1. Locate `settings.json`

- Windows: `C:\Windows\ServiceProfiles\LocalService\AppData\Local\transmission-daemon\settings.json`

2. open file and edit

```json
{
    "blocklist-enabled": true,
    "blocklist-url": "https://raw.githubusercontent.com/FriesI23/transmission-block-list/master/block.txt"
}
```

