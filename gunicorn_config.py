# gunicorn_config.py
import multiprocessing

# Worker processes
workers = 2
worker_class = 'sync'

# Timeout settings (critical for Render.com)
timeout = 120  # 2 minutes instead of default 30 seconds
keepalive = 5

# Worker connections
worker_connections = 1000

# Logging
accesslog = '-'
errorlog = '-'