import colorama
import os

colorama.init(autoreset=True)

# Read from environment variables for Docker compatibility, fallback to defaults
DEFAULT_HOST = os.getenv("SERVER_HOST", "localhost")
DEFAULT_PORT = int(os.getenv("SERVER_PORT", "9000"))
DEFAULT_ROOM = "general"
COLORS = [
    colorama.Fore.RED,
    colorama.Fore.GREEN,
    colorama.Fore.YELLOW,
    colorama.Fore.BLUE,
    colorama.Fore.MAGENTA,
    colorama.Fore.CYAN,
    colorama.Fore.WHITE,
    colorama.Fore.LIGHTRED_EX,
]
