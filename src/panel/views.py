from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from .get_log import get_logs
from .config import get_whitelist, get_blacklist
from .stats import get_proxy_stats

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def admin_page():
    logs = get_logs(num_lines=100)
    total_requests, cache_hits, allowed_requests, blocked_requests = get_proxy_stats()
    whitelist = get_whitelist()
    blacklist = get_blacklist()

    return f"""
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Admin Panel</title>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/script.js" defer></script>
</head>

<body>

    <header>
        <h1>Proxy Admin Panel</h1>
    </header>

    <div class="container">
        <section class="stats">
            <h2>Proxy Stats</h2>
            <ul>
                <li><strong>Total Requests:</strong> {total_requests}</li>
                <li><strong>Cache Hits:</strong> {cache_hits}</li>
                <li><strong>Allowed Requests:</strong> {allowed_requests}</li>
                <li><strong>Blocked Requests:</strong> {blocked_requests}</li>
            </ul>
        </section>

        <section class="logs">
            <h2>Logs</h2>
            <pre>{'\n'.join(logs)}</pre>
        </section>
        
        <section class="logs">
            <h2>Whitelist</h2>
            <pre>{'\n'.join(whitelist)}</pre>
        </section>
        
        <section class="logs">
            <h2>Blacklist</h2>
            <pre>{'\n'.join(blacklist)}</pre>
        </section>
        
    <footer>
        <p>&copy; 2024 Proxy Admin Panel. All Rights Reserved.</p>
    </footer>

</body>

</html>
    """