import os

LOG_PATH = "../logs/app.log"

def get_proxy_stats() -> tuple[int, int, int, int]:
    """
    Return statistics on the proxy, such as total requests, cache hits, and allowed/blocked counts.
    """

    # grep log file for stats
    total_requests_command = f"grep -i 'connection established' ../logs/app*log* | wc -l"
    cache_hits_command = f"grep -i 'cache hit' {LOG_PATH} | wc -l"
    allowed_requests_command = f"grep allowlist {LOG_PATH} | grep -e 'allowing' -e 'whitelisted' | wc -l"
    blocked_requests_command = f"grep allowlist {LOG_PATH} | grep 'blacklisted' | wc -l"

    total_requests = int(os.popen(total_requests_command).read())
    cache_hits = int(os.popen(cache_hits_command).read())
    allowed_requests = int(os.popen(allowed_requests_command).read())
    blocked_requests = int(os.popen(blocked_requests_command).read())

    return total_requests, cache_hits, allowed_requests, blocked_requests
