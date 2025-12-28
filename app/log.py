from datetime import datetime

def log_info(message):
    print(f"\033[92m[{datetime.now().isoformat()}] INFO: {message}\033[0m")  # Green

def log_error(message):
    print(f"\033[91m[{datetime.now().isoformat()}] ERROR: {message}\033[0m")  # Red

def log_debug(message):
    print(f"\033[94m[{datetime.now().isoformat()}] DEBUG: {message}\033[0m")  # Blue

TIDE = r"""
===============================
 _______   _   _____    _______
|__   __| | | |  __ \  |  _____|
   | |    | | | |  | | | |_____
   | |    | | | |  | | |  _____|
   | |    | | | |__| | | |_____
~`~|~|~`~`|~|~|~____/`~|~`~`~`~|~
~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~`~
===============================
"""
def logo_sigea():
    print(f"\033[96m{TIDE}\033[0m")  # Blue

tide3d = r"""
==============================
######## ## ######   #####
   ##    ## ##   ##  ##
   ##    ## ##    ## ####
   ##    ## ##   ##  ##
   ##    ## ######   ######
==============================
"""
def logo_sigea():
    print(f"\033[96m{tide3d}\033[0m")  # Blue