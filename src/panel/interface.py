# Author: Bryan El Medawar

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .views import admin_page
from .config import get_whitelist, get_blacklist
from .get_log import get_logs
from .stats import get_proxy_stats
import logging

logger = logging.getLogger('interface')

app = FastAPI()

# Static files for frontend (e.g., for CSS, JS, or HTML templates)
app.mount("/static", StaticFiles(directory="panel/static"), name="static")

# Admin panel endpoint
app.get("/", response_class=HTMLResponse)(admin_page)


# Log management
@app.get("/logs/")
def fetch_logs():
    logger.debug("Fetching logs")
    return get_logs()


# Blacklist/Whitelist management
@app.get("/whitelist/")
def fetch_whitelist():
    logger.debug("Fetching whitelist")
    return get_whitelist()


@app.get("/blacklist/")
def fetch_blacklist():
    logger.debug("Fetching blacklist")
    return get_blacklist()


# Proxy stats
@app.get("/proxy-stats/")
def proxy_stats():
    logger.debug("Fetching proxy stats")
    return get_proxy_stats()