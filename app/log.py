"""The older modules' log calls (elastic_helper, cti_helper, app/database.py). They go to TIDE's log,
under the calling module's name, so they reach data/log/tide.log and Diagnostics with the request,
client and run they belong to, and an error with its code (#117). A script that hasn't set up
logging gets them printed, as before."""
import logging
import sys
from datetime import datetime

_COLOURS = {logging.INFO: "92", logging.ERROR: "91", logging.DEBUG: "94"}   # green, red, blue


def _log(level, message):
    if not logging.getLogger().handlers:
        print(f"\033[{_COLOURS[level]}m[{datetime.now().isoformat()}] {logging.getLevelName(level)}: {message}\033[0m")
        return
    extra = {}
    if level >= logging.ERROR and sys.exc_info()[1] is not None:
        from app.services.errors import classify      # called while handling an exception: its code
        extra["code"] = classify(sys.exc_info()[1]).code
    logging.getLogger(sys._getframe(2).f_globals.get("__name__", "tide")).log(level, message, extra=extra, stacklevel=3)


def log_info(message):
    _log(logging.INFO, message)


def log_error(message):
    _log(logging.ERROR, message)


def log_debug(message):
    _log(logging.DEBUG, message)

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