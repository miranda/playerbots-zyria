# Playerbots Fork Modified for Zyria LLM Server Support

This is a modified version of the [Playerbots module](https://github.com/cmangos/playerbots) designed to integrate with the [Zyria LLM Server](https://github.com/miranda/zyria) — a Python-based local LLM server optimized for realistic, context-aware playerbot conversations in cMaNGOS.

This fork introduces native support for the Zyria API while remaining compatible with generic LLM APIs supported by the official project. If you want your bots to engage in immersive, human-like chat using local language models, this is the fork you’ll need.

Zyria is a custom LLM server written in Python that brings a new level of realism to the LLM chat supported by the Playerbot module.  It is highly configurable and has many advanced features, including bot personalities, memories, and is more game context-aware than a standard LLM server.

Learn more about Zyria and get it running with cMaNGOS/Playerbots here:
[https://github.com/miranda/zyria](https://github.com/miranda/zyria)

---

## Key Differences from Upstream Playerbots

- Adds built-in Zyria API client functions for enhanced, realistic playerbot conversations when using the Zyria server.
- Custom configuration options in `aiplayerbot.conf` for controlling special Zyria features added in the fork.
- If Zyria support is disabled in `aiplayerbot.conf` the module will function like the official module, allowing you to still use other LLM servers such as Kobold.cpp — No need to rebuild cMaNGOS.
- Occasionally there may be some minor bug fixes not in the official Playerbots module.

---
> **TL;DR Setup Summary**:
> 1. Replace `PlayerBots` folder with this fork
> 2. Build with `-DBUILD_PLAYERBOTS=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON`
> 3. Copy `aiplayerbot.conf.dist` → `aiplayerbot.conf`
> 4. Install Zyria → [Zyria Repo](https://github.com/miranda/zyria)
> 5. Configure LLM section in `aiplayerbot.conf` + Zyria config
> 6. Enjoy smarter, chatty playerbots with personalities

---

## Installation

### 1. Clone and Replace the Playerbots Module

If you're already working with a cMaNGOS source tree:

Remove the existing `src/modules/PlayerBots` directory and clone or copy this repository's contents into the same location.
```
rm -rf src/modules/PlayerBots
git clone https://github.com/miranda/playerbots-zyria src/modules/PlayerBots
```
### 2. Build cMaNGOS with Playerbots Enabled
Follow the official CMaNGOS installation guide and the official Playerbots installation guide (below), but during the CMake step ensure you have this option enabled:
```
-DFETCHCONTENT_FULLY_DISCONNECTED=ON
```
For example, your build configuration might look like this:
```
cmake ../mangos-tbc \
    -DCMAKE_INSTALL_PREFIX=$HOME/cmangos/run \
    -DPCH=\
    -DDEBUG=0 \
    -DBUILD_PLAYERBOTS=ON \
    -DBUILD_AHBOT=false \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON
```
It is critical to set `-DFETCHCONTENT_FULLY_DISCONNECTED` in order to prevent the standard Playerbots module from being downloaded over playerbots-zyria.

### 3. Copy and Configure Playerbot Settings
After building, locate the provided configuration template and copy it to your server config directory:
```
cd ~/cmangos/run/etc/
cp aiplayerbot.conf.dist aiplayerbot.conf
```
The modified .dist files includes some Zyria-specific settings in the LLM section, as well as a few modified defaults compared to the files packaged with the standard Playerbots module.
Note: Be sure to backup your standard aiplayerbot.conf file if you have made changes to it and want to duplicate the non-LLM settings in the new file.

The bulk of Zyria's configuration settings are located in its own config files.
See the [Zyria README](https://github.com/miranda/zyria) for detailed configuration instructions.

Below is the standard Playerbots README:

---

# Playerbots
Bot AI Core from ike3 for cmangos classic, tbc and wotlk

This system brings the following features:
- Populate the open world with playerbots
- Populate BGs and Arenas with playerbots
- Use alt characters as playerbots
- Do any kind of PvE content (with some guidance on complex mechanics)
- Very detailed configurations of playerbot behaviors (for the min-maxers out there :D)
- Multiple commands to request playerbots do what you require

# How to install
## Compiling Code
If you're new to building CMaNGOS, check the official guide
https://github.com/cmangos/issues/wiki/Installation-Instructions

Important: to enable the playerbots you need to check it in cmake ( `BUILD_PLAYERBOTS` ✅ )

After successful build get aiplayerbot.conf file from "src/modules/Bots/playerbot/aiplayerbot%expansion.conf.dist" (based on expansion you use) and put it to the same folder where mangosd.conf and realmd.conf are, and remove ".dist" from its name

## Apply DB modifications
- Using the `InstallFullDB.sh` script:
  1. Execute the script once to generate the `InstallFullDB.config` file, after that close the script
  2. Edit `InstallFullDB.config` and add `PLAYERBOTS_DB="YES"` at the end and save it
  3. Depending on if you have a previous installation or want to do a fresh installation:
     - For a fresh install pick the option `4) Full installation`
     - To install only the playerbots DB pick the option `5) Advanced DB management` and then `8) Create and fill playerbots db`

- Manually:
  1.  Go to "src/modules/Bots/sql"
  2.  Apply .sql files from "characters" folder to characters database
  3.  Apply .sql files from "world" folder to world database
  
  **IMPORTANT**: There are several .sql files that are in a `vanilla`, `tbc` or `wotlk` folder. You should only use the files in the folder for the core expansion you are currently using.

After you complete all steps above you can check bots config and start your server. It'll take some time for the first time, as gear/characters for bots will be generated at first launch. Have fun! 🥳

## How to Use
- [List of Commands](https://docs.google.com/document/d/1xIdu5l5lAKLSKhqZ2Hb6vaU8qJgbbLwCw4MxmhCW_gI/edit#heading=h.vsmxe9r82yc7)
- [Playerbots Behavior AddOn](https://github.com/celguar/mangosbot-addon)
- [Playerbot Inventory AddOn](https://github.com/davidonete/mangosbot-EngBags)
- [Playerbots Discord Channel](https://discord.gg/vmjZUnPUdr)

