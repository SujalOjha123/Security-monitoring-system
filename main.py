from web.app import app, socketio, start_log_watcher


if __name__ == "__main__":
    start_log_watcher()
    socketio.run(app, host="127.0.0.1", port=5000)
