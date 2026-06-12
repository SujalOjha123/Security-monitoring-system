from collector.fetch_logs import stream_logs


def print_log(line):
    print("LOG:", line)


stream_logs(print_log)