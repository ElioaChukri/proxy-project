document.getElementById('restart-btn').addEventListener('click', async () => {
    if (confirm("Are you sure you want to restart the server?")) {
// Send POST request to /restart
        try {
            await fetch('/restart', {method: 'POST'});

// Redirect to "/" after sending the request
            window.location.href = "/";
        } catch (error) {
            window.location = "/";
        }
    }
});