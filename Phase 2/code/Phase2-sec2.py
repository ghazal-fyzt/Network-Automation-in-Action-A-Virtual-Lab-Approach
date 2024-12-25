#!/usr/bin/env python3

import curses
import ipaddress
import os
import subprocess
import logging

phase2_logger = logging.getLogger("phase2_logger")
phase2_logger.setLevel(logging.INFO)
p2_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
p2_handler = logging.FileHandler('phase2.log')
p2_handler.setLevel(logging.INFO)
p2_handler.setFormatter(p2_formatter)
phase2_logger.addHandler(p2_handler)

def print_wrapped(screen, start_y, start_x, text, max_width):
    if len(text) > max_width:
        text = text[:max_width-1]
    screen.addstr(start_y, start_x, text)

def message_box(screen, message):
    screen.clear()
    screen.border(0)
    lines = message.split('\n')
    max_y, max_x = screen.getmaxyx()
    y = 2
    for line in lines:
        if y >= max_y - 2:
            break
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1
    if y < max_y - 2:
        print_wrapped(screen, y+1, 2, "Press any key to continue...", max_x - 4)
    screen.refresh()
    screen.getch()

def input_box(screen, prompt):
    curses.noecho()
    screen.clear()
    screen.border(0)
    max_y, max_x = screen.getmaxyx()

    lines = prompt.split('\n')
    y = 2
    for line in lines:
        if y >= max_y - 2:
            break
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1

    print_wrapped(screen, y+1, 2, "(Press ESC or 'back' to return)", max_x - 4)
    input_y = y + 3
    input_x = 2
    screen.move(input_y, input_x)
    screen.refresh()

    buffer = []
    curses.curs_set(1)
    while True:
        ch = screen.getch()
        if ch == 27:
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 127):
            if buffer:
                buffer.pop()
                screen.delch(input_y, input_x + len(buffer))
        elif ch in (10, 13):
            user_input = "".join(buffer).strip()
            curses.curs_set(0)
            if user_input.lower() == 'back':
                return None
            return user_input
        elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_UP, curses.KEY_DOWN):
            continue
        else:
            if 32 <= ch <= 126:
                buffer.append(chr(ch))
                screen.addch(input_y, input_x + len(buffer)-1, ch)

def run_command(cmd):
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)

def flush_all_rules():
    try:
        subprocess.check_call(["nft", "flush", "ruleset"])
        phase2_logger.info("Flushed all nftables rules.")
    except Exception as e:
        phase2_logger.error(f"Failed to flush ruleset: {e}")

def remove_and_reinstall_nftables():
    try:
        run_command(["apt-get", "remove", "-y", "nftables"])
        run_command(["apt-get", "purge", "-y", "nftables"])
        run_command(["apt-get", "autoremove", "-y"])
        run_command(["apt-get", "install", "-y", "nftables"])
        phase2_logger.info("Removed and reinstalled nftables.")
    except Exception as e:
        phase2_logger.error(f"Failed to remove/reinstall nftables: {e}")

def final_nft_attempt(screen):
    try:
        run_command(["systemctl", "enable", "nftables"])
        run_command(["systemctl", "start", "nftables"])
        phase2_logger.info("Finally started nftables.service.")
    except Exception as e:
        phase2_logger.error(f"Last resort attempt failed to start nftables: {e}")
        message_box(screen, "Could not start nftables even after last resort.")

def ensure_nftables_conf(screen):
    conf_path = "/etc/nftables.conf"
    if not os.path.exists(conf_path) or os.path.getsize(conf_path) == 0:
        default_conf = """#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
    }
}
table ip nat {
    chain prerouting {
        type nat hook prerouting priority 0; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
    }
}
"""
        try:
            with open(conf_path, 'w') as f:
                f.write(default_conf)
        except Exception as e:
            message_box(screen, f"Error creating {conf_path}:\n{e}")

def check_nft_installed_phase2(screen):
    try:
        subprocess.check_output(["which", "nft"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        message_box(screen, "nft not found.\nAttempting to install nftables.")
        try:
            run_command(["apt-get", "update"])
            run_command(["apt-get", "install", "-y", "nftables"])
            phase2_logger.info("Installed nftables.")
        except Exception as e:
            phase2_logger.error(f"Failed to install nftables: {e}")
            return False
    # check service
    try:
        status = subprocess.check_output(["systemctl", "is-active", "nftables"], universal_newlines=True).strip()
        if status != "active":
            try:
                run_command(["systemctl", "enable", "nftables"])
                run_command(["systemctl", "start", "nftables"])
                phase2_logger.info("Enabled & started nftables.service.")
            except Exception as e:
                phase2_logger.warning(f"Failed to enable/start nftables.service:\n{e}")
                flush_all_rules()
                remove_and_reinstall_nftables()
                final_nft_attempt(screen)
    except subprocess.CalledProcessError as se:
        phase2_logger.warning(f"systemctl is-active nftables failed: {se}")
        flush_all_rules()
        remove_and_reinstall_nftables()
        final_nft_attempt(screen)

    ensure_nftables_conf(screen)
    return True

def apply_nft_rule(screen, rule, nat=False):
    conf_path = "/etc/nftables.conf"
    if nat:
        if "masquerade" in rule:
            full_rule = f"add rule ip nat postrouting {rule}\n"
        elif "dnat to" in rule:
            full_rule = f"add rule ip nat prerouting {rule}\n"
        else:
            phase2_logger.error("Unknown NAT rule pattern: " + rule)
            message_box(screen, "Error: Unknown NAT rule pattern.")
            return
    else:
        full_rule = f"add rule inet filter input {rule}\n"

    try:
        with open(conf_path, 'a') as f:
            f.write(full_rule)
        run_command(["nft", "-f", conf_path])
        message_box(screen, "Rule added successfully!")
        phase2_logger.info(f"Added nftables rule: {full_rule.strip()}")
    except Exception as e:
        phase2_logger.error(f"Error applying nft rule: {e}")
        message_box(screen, f"Error applying rule:\n{e}")

def validate_ip_input_phase2(screen, prompt):
    while True:
        val = input_box(screen, prompt)
        if val is None:
            return None
        try:
            ipaddress.IPv4Address(val)
            return val
        except:
            message_box(screen, f"Invalid IP: {val}")

def ct_state_rule_form(screen):
    allowed_states = ["established", "related", "invalid", "new"]
    allowed_actions = ["accept", "drop", "reject"]
    st = input_box(screen, f"Enter ct state ({'/'.join(allowed_states)}):")
    if st is None:
        return
    while st not in allowed_states:
        message_box(screen, f"Invalid state: {st}")
        st = input_box(screen, f"Re-enter state ({'/'.join(allowed_states)}):")
        if st is None:
            return
    act = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if act is None:
        return
    while act not in allowed_actions:
        message_box(screen, f"Invalid action: {act}")
        act = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if act is None:
            return

    rule = f"ct state {st} {act}"
    apply_nft_rule(screen, rule, nat=False)

def ip_proto_rule_form(screen):
    src = validate_ip_input_phase2(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input_phase2(screen, "Enter destination IP:")
    if dst is None:
        return
    allowed_protocols = ["tcp", "udp"]
    proto = input_box(screen, f"Enter protocol ({'/'.join(allowed_protocols)}):")
    if proto is None:
        return
    while proto not in allowed_protocols:
        message_box(screen, f"Invalid protocol: {proto}")
        proto = input_box(screen, f"Re-enter protocol ({'/'.join(allowed_protocols)}):")
        if proto is None:
            return
    dport = input_box(screen, "Enter destination port (1-65535):")
    if dport is None:
        return
    if not dport.isdigit() or not (1 <= int(dport) <= 65535):
        message_box(screen, f"Invalid port: {dport}")
        return
    allowed_actions = ["accept", "drop", "reject"]
    act = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if act is None:
        return
    while act not in allowed_actions:
        message_box(screen, f"Invalid action: {act}")
        act = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if act is None:
            return
    rule = f"ip saddr {src} ip daddr {dst} {proto} dport {dport} {act}"
    apply_nft_rule(screen, rule, nat=False)

def icmp_rule_form(screen):
    src = validate_ip_input_phase2(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input_phase2(screen, "Enter destination IP:")
    if dst is None:
        return
    allowed_types = ["echo-request", "destination-unreachable"]
    icmp_type = input_box(screen, f"Enter ICMP type ({'/'.join(allowed_types)}):")
    if icmp_type is None:
        return
    while icmp_type not in allowed_types:
        message_box(screen, f"Invalid ICMP type: {icmp_type}")
        icmp_type = input_box(screen, f"Re-enter ICMP type ({'/'.join(allowed_types)}):")
        if icmp_type is None:
            return
    allowed_actions = ["accept", "drop"]
    act = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if act is None:
        return
    while act not in allowed_actions:
        message_box(screen, f"Invalid action: {act}")
        act = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if act is None:
            return
    rule = f"ip saddr {src} ip daddr {dst} icmp type {icmp_type} {act}"
    apply_nft_rule(screen, rule, nat=False)

def masquerade_rule_form(screen):
    src = validate_ip_input_phase2(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input_phase2(screen, "Enter destination IP:")
    if dst is None:
        return
    rule = f"ip saddr {src} ip daddr {dst} masquerade"
    apply_nft_rule(screen, rule, nat=True)

def dnat_rule_form(screen):
    src = validate_ip_input_phase2(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input_phase2(screen, "Enter destination IP:")
    if dst is None:
        return
    dport = input_box(screen, "Enter destination port (1-65535):")
    if dport is None:
        return
    if not dport.isdigit() or not (1 <= int(dport) <= 65535):
        message_box(screen, f"Invalid port: {dport}")
        return
    new_target = input_box(screen, "Enter DNAT target (IP:PORT):")
    if new_target is None:
        return
    if ':' not in new_target:
        message_box(screen, "Invalid DNAT target format (use IP:PORT).")
        return
    ip_part, port_part = new_target.split(':', 1)
    try:
        ipaddress.IPv4Address(ip_part)
    except:
        message_box(screen, f"Invalid IP in DNAT target: {ip_part}")
        return
    if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
        message_box(screen, f"Invalid port in DNAT target: {port_part}")
        return
    rule = f"ip saddr {src} ip daddr {dst} tcp dport {dport} dnat to {new_target}"
    apply_nft_rule(screen, rule, nat=True)

def nftables_menu(screen):
    if not check_nft_installed_phase2(screen):
        return
    selected = 0
    options = [
        "Create ct_state rule",
        "Create IP-based rule",
        "Create ICMP rule",
        "Create masquerade rule",
        "Create DNAT rule",
        "Exit Phase 2"
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Phase 2: Nftables Management (ESC to exit)", max_x - 4)
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + opt, max_x - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:
            if selected == 0:
                ct_state_rule_form(screen)
            elif selected == 1:
                ip_proto_rule_form(screen)
            elif selected == 2:
                icmp_rule_form(screen)
            elif selected == 3:
                masquerade_rule_form(screen)
            elif selected == 4:
                dnat_rule_form(screen)
            elif selected == 5:
                break
        elif key == 27:
            break

def main(stdscr):
    if os.geteuid() != 0:
        stdscr.clear()
        stdscr.border(0)
        message_box(stdscr, "Error: Must run as root.\nPress any key to exit.")
        return
    nftables_menu(stdscr)

if __name__ == '__main__':
    curses.wrapper(main)
