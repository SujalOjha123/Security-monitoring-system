import re


ACCESS_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

REQUEST_PATTERN = re.compile(
    r'(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>HTTP/\d(?:\.\d)?))?'
)


def parse_log_line(line):
    match = ACCESS_LOG_PATTERN.match(line)
    if not match:
        return {
            "matched": False,
            "raw": line,
        }

    parsed = match.groupdict()
    request = parsed.get("request") or ""
    request_match = REQUEST_PATTERN.match(request)

    parsed["matched"] = True
    parsed["raw"] = line
    parsed["method"] = request_match.group("method") if request_match else ""
    parsed["path"] = request_match.group("path") if request_match else request
    parsed["protocol"] = request_match.group("protocol") if request_match else ""

    return parsed
