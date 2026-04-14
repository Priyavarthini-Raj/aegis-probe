# log_generator.py
# Generates realistic sample security log files for testing

import random
from datetime import datetime, timedelta


def generate_ssh_logs(filename="D:\\aegis_probe\\logs\\ssh_attack.log", lines=100):
    """Generates SSH brute force attack logs"""
    ips = ["89.248.167.131", "45.155.205.233", "185.220.101.45",
           "192.168.1.10", "192.168.1.11"]
    users = ["root", "admin", "ubuntu", "user", "test", "oracle"]

    log_lines = []
    base_time = datetime.now() - timedelta(hours=2)

    for i in range(lines):
        timestamp = base_time + timedelta(seconds=i * 3)
        ip = random.choice(ips)
        user = random.choice(users)
        ts = timestamp.strftime("%b %d %H:%M:%S")

        if random.random() < 0.85:
            log_lines.append(
                f"{ts} server sshd[1234]: Failed password for {user} "
                f"from {ip} port {random.randint(1024,65535)} ssh2"
            )
        else:
            log_lines.append(
                f"{ts} server sshd[1234]: Accepted password for {user} "
                f"from {ip} port {random.randint(1024,65535)} ssh2"
            )

    with open(filename, "w") as f:
        f.write("\n".join(log_lines))
    print(f"[+] SSH log generated: {filename}")
    return filename


def generate_web_logs(filename="D:\\aegis_probe\\logs\\web_attack.log", lines=80):
    """Generates web server attack logs"""
    ips = ["193.32.162.95", "45.33.32.156", "185.156.73.54",
           "10.0.0.1", "10.0.0.2"]
    paths = [
        "/admin", "/wp-admin", "/login",
        "/?id=1' OR '1'='1",
        "/etc/passwd",
        "/../../../etc/shadow",
        "/shell.php",
        "/index.php",
        "/api/users"
    ]
    methods = ["GET", "POST", "PUT"]
    codes = [200, 200, 301, 403, 404, 500]

    log_lines = []
    base_time = datetime.now() - timedelta(hours=1)

    for i in range(lines):
        timestamp = base_time + timedelta(seconds=i * 5)
        ip = random.choice(ips)
        path = random.choice(paths)
        method = random.choice(methods)
        code = random.choice(codes)
        ts = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        log_lines.append(
            f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" '
            f'{code} {random.randint(200, 5000)}'
        )

    with open(filename, "w") as f:
        f.write("\n".join(log_lines))
    print(f"[+] Web log generated: {filename}")
    return filename


def generate_firewall_logs(filename="D:\\aegis_probe\\logs\\firewall.log", lines=60):
    """Generates firewall logs"""
    ips = ["91.195.240.94", "194.165.16.76", "46.161.27.151",
           "185.220.101.34", "10.0.0.5"]
    ports = [22, 80, 443, 3306, 3389, 8080, 21, 23, 3333]
    actions = ["BLOCK", "BLOCK", "BLOCK", "ALLOW"]

    log_lines = []
    base_time = datetime.now() - timedelta(hours=3)

    for i in range(lines):
        timestamp = base_time + timedelta(seconds=i * 10)
        src_ip = random.choice(ips)
        dst_port = random.choice(ports)
        action = random.choice(actions)
        ts = timestamp.strftime("%Y-%m-%d %H:%M:%S")

        log_lines.append(
            f"{ts} FIREWALL {action} src={src_ip} "
            f"dst=10.0.0.1 dport={dst_port} "
            f"proto=TCP bytes={random.randint(40, 1500)}"
        )

    with open(filename, "w") as f:
        f.write("\n".join(log_lines))
    print(f"[+] Firewall log generated: {filename}")
    return filename


def generate_all_logs():
    """Generates all sample log files"""
    import os
    os.makedirs("D:\\aegis_probe\\logs", exist_ok=True)
    generate_ssh_logs()
    generate_web_logs()
    generate_firewall_logs()
    print("\n✅ All sample logs generated in D:\\aegis_probe\\logs\\")


if __name__ == "__main__":
    generate_all_logs()