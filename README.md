
# Watchdog

The **Watchdog** is a Discord bot designed to provide quick and easy removal of scammer/spam bots. Fully stripped down version of the MiloHax Info Bot.

## Features

In a 9 second timespan, if the same exact message is sent in 3 channels, the user gets "soft-banned" which is effectively banned then unbanned (specifically for the purpose of message removal).

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/metriccepheid/nhxinfobot.git -b watchdog
   cd nhxinfobot
   ```

2. **Install Dependencies**:
   Ensure you have Python installed. Install the required Python packages using pip:
   ```bash
   pip install discord.py
   ```

3. **Configuration**:
   - Make sure you open the **watchdog.py** to edit where the messages for when a bot gets banned are sent.

4. **Run the Bot**:<br />
   Start the bot by running:
   ```bash
   python watchdog.py
   ```

## Contributing

Contributions are welcome! If you have ideas for additional triggers or improvements to the bot, feel free to open a pull request or submit an issue.