# Spectyr MUST run as a single worker process: sessions live in an in-memory
# dict and each active session runs a log-writer thread inside this process.
# A second worker would get its own empty session store and no threads, so
# requests routed to it would silently create duplicate sessions and dead
# simulations. Do not "scale" this with -w on the start command — that flag
# would override this file.
workers = 1

# Concurrency comes from threads instead; they all share the session dict.
threads = 8
