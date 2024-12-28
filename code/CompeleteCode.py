import curses
import ipaddress
import os
import subprocess
import logging
import time

# ------------------ Phase 1 Logger ------------------ #
phase1_logger = logging.getLogger("phase1_logger")
phase1_logger.setLevel(logging.INFO)
phase1_formatter = logging.Formatter("%(asctime)s %(levelname)s:%(message)s")
phase1_file_handler = logging.FileHandler("phase1.log")
phase1_file_handler.setLevel(logging.INFO)
phase1_file_handler.setFormatter(phase1_formatter)
phase1_logger.addHandler(phase1_file_handler)

# ------------------ Phase 2 Logger ------------------ #
phase2_logger = logging.getLogger("phase2_logger")
phase2_logger.setLevel(logging.INFO)
phase2_formatter = logging.Formatter("%(asctime)s %(levelname)s:%(message)s")
phase2_file_handler = logging.FileHandler("phase2.log")
phase2_file_handler.setLevel(logging.INFO)
phase2_file_handler.setFormatter(phase2_formatter)
phase2_logger.addHandler(phase2_file_handler)

# ------------------ Phase 3 Logger ------------------ #
phase3_logger = logging.getLogger("phase3_logger")
phase3_logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s:%(message)s")
file_handler = logging.FileHandler("phase3.log")
file_handler.setFormatter(formatter)
phase3_logger.addHandler(file_handler)

# ------------------ Phase 4 Logger ------------------ #
phase4_logger = logging.getLogger("phase4_logger")
phase4_logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(levelname)s:%(message)s")
file_handler = logging.FileHandler("phase4.log")
file_handler.setFormatter(formatter)
phase4_logger.addHandler(file_handler)

##############################################
# Common Helper Functions (Printing, Input)  #
##############################################


def print_wrapped(screen, start_y, start_x, text, max_width):
    """
    Print text at (start_y, start_x) with truncation if needed.
    Helps maintain alignment in limited terminal widths.
    """
    if len(text) > max_width:
        text = text[: max_width - 1]
    screen.addstr(start_y, start_x, text)


def message_box(screen, message):
    """
    Display a message in a box. The user presses a key to continue.
    Useful for confirmations, errors, or notifications.
    """
    screen.clear()
    screen.border(0)
    lines = message.split("\n")
    max_y, max_x = screen.getmaxyx()
    y = 2
    for line in lines:
        if y >= max_y - 2:
            break
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1
    if y < max_y - 2:
        print_wrapped(screen, y + 1, 2, "Press any key to continue...", max_x - 4)
    screen.refresh()
    screen.getch()


def input_box(screen, prompt):
    """
    Prompt user for input with a single line.
    Press ESC or type 'back' to return None (go back).
    """
    curses.noecho()
    screen.clear()
    screen.border(0)
    max_y, max_x = screen.getmaxyx()
    lines = prompt.split("\n")
    y = 2
    for line in lines:
        if y >= max_y - 2:
            break
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1

    print_wrapped(screen, y + 1, 2, "(Press ESC or type 'back' to return)", max_x - 4)
    input_y = y + 3
    input_x = 2
    screen.move(input_y, input_x)
    screen.refresh()

    buffer = []
    curses.curs_set(1)
    while True:
        ch = screen.getch()
        if ch == 27:  # ESC
            curses.curs_set(0)
            return None
        elif ch in (curses.KEY_BACKSPACE, 127):
            if buffer:
                buffer.pop()
                screen.delch(input_y, input_x + len(buffer))
        elif ch in (10, 13):  # Enter
            user_input = "".join(buffer).strip()
            curses.curs_set(0)
            if user_input.lower() == "back":
                return None
            return user_input
        elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_UP, curses.KEY_DOWN):
            continue
        else:
            if 32 <= ch <= 126:
                buffer.append(chr(ch))
                screen.addch(input_y, input_x + len(buffer) - 1, ch)


def run_command(cmd):
    """
    Run a shell command quietly, raise on failure.
    """
    with open(os.devnull, "w") as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)


##################################
# Phase 1: Network Configuration #
##################################


def validate_ip(ip_str):
    """Check if ip_str is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except:
        return False


def get_network_interfaces():
    """Return list of interfaces from /sys/class/net."""
    return os.listdir("/sys/class/net/")


def route_exists(destination_cidr, gateway, interface_name):
    """Check if a route exists in the system routing table."""
    output = subprocess.check_output(["ip", "route", "show"], universal_newlines=True)
    route_line = f"{destination_cidr} via {gateway} dev {interface_name}"
    return route_line in output


def add_route_temporary(interface_name, destination_cidr, gateway):
    cmd = [
        "ip",
        "route",
        "add",
        destination_cidr,
        "via",
        gateway,
        "dev",
        interface_name,
    ]
    subprocess.check_call(cmd)
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after addition.")


def add_route_permanent(interface_name, destination_cidr, gateway):
    run_command(
        [
            "nmcli",
            "connection",
            "modify",
            interface_name,
            "+ipv4.routes",
            f"{destination_cidr} {gateway}",
        ]
    )
    run_command(["nmcli", "connection", "up", interface_name])
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after permanent addition.")


def remove_route_temporary(interface_name, destination_cidr, gateway):
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route does not exist.")
    cmd = [
        "ip",
        "route",
        "del",
        destination_cidr,
        "via",
        gateway,
        "dev",
        interface_name,
    ]
    subprocess.check_call(cmd)


def change_dns(interface_name, dns_list, permanent):
    if permanent:
        run_command(
            [
                "nmcli",
                "connection",
                "modify",
                interface_name,
                "ipv4.dns",
                ",".join(dns_list),
            ]
        )
        run_command(["nmcli", "connection", "up", interface_name])
    else:
        for dns in dns_list:
            run_command(["resolvectl", "dns", interface_name, dns])


def change_hostname(new_hostname):
    run_command(["hostnamectl", "set-hostname", new_hostname])


def set_static_ip(interface_name, ip_address, subnet_mask, gateway, permanent):
    cidr = f"{ip_address}/{subnet_mask}"
    if permanent:
        run_command(
            ["nmcli", "connection", "modify", interface_name, "ipv4.addresses", cidr]
        )
        if gateway:
            run_command(
                [
                    "nmcli",
                    "connection",
                    "modify",
                    interface_name,
                    "ipv4.gateway",
                    gateway,
                ]
            )
        run_command(
            ["nmcli", "connection", "modify", interface_name, "ipv4.method", "manual"]
        )
        run_command(["nmcli", "connection", "up", interface_name])
    else:
        run_command(["ip", "addr", "flush", "dev", interface_name])
        run_command(["ip", "addr", "add", cidr, "dev", interface_name])
        if gateway:
            run_command(
                ["ip", "route", "add", "default", "via", gateway, "dev", interface_name]
            )


def use_dhcp(interface_name):
    run_command(
        ["nmcli", "connection", "modify", interface_name, "ipv4.method", "auto"]
    )
    run_command(["nmcli", "connection", "up", interface_name])


#################
# Phase 1: TUI  #
#################
import curses

phase1_logger = logging.getLogger("phase1_logger")


def select_interface(screen):
    interfaces = get_network_interfaces()
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(
            screen, 2, 2, "Select Interface (ESC to go back)", screen.getmaxyx()[1] - 4
        )
        for idx, iface in enumerate(interfaces):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + iface, screen.getmaxyx()[1] - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(interfaces) - 1:
            selected += 1
        elif key in [10, 13]:
            return interfaces[selected]
        elif key == 27:
            return None


def select_permanence(screen):
    options = ["Temporarily", "Permanently", "Back"]
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(screen, 2, 2, "Apply Change:", screen.getmaxyx()[1] - 4)
        for idx, option in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + option, screen.getmaxyx()[1] - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:
            if options[selected] == "Back":
                return None
            return selected == 1
        elif key == 27:
            return None


def change_dns_form(screen):
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        while True:
            dns_servers = input_box(
                screen, "Enter up to 3 DNS Servers (comma-separated):"
            )
            if dns_servers is None:
                break
            if dns_servers == "":
                message_box(screen, "DNS Servers cannot be empty!")
                continue
            dns_list = [dns.strip() for dns in dns_servers.split(",") if dns.strip()]
            if len(dns_list) == 0:
                message_box(screen, "No valid DNS servers entered!")
                continue
            if len(dns_list) > 3:
                message_box(screen, "You entered more than 3 DNS servers.")
                continue

            # Validate each DNS
            all_good = True
            for d in dns_list:
                if not validate_ip(d):
                    all_good = False
                    message_box(screen, f"Invalid DNS IP: {d}")
                    break
            if not all_good:
                continue

            p = select_permanence(screen)
            if p is None:
                break
            permanent = p
            try:
                change_dns(interface, dns_list, permanent)
                message_box(screen, "DNS updated successfully!")
                phase1_logger.info(
                    f"DNS updated to {dns_list} on {interface}, permanent={permanent}"
                )
                return
            except Exception as e:
                phase1_logger.error(f"Error updating DNS: {e}")
                message_box(screen, f"Error: {e}")
        return


def change_hostname_form(screen):
    while True:
        newname = input_box(screen, "Enter New Hostname:")
        if newname is None:
            return
        if not newname:
            message_box(screen, "Hostname cannot be empty!")
            continue
        try:
            change_hostname(newname)
            message_box(screen, "Hostname changed successfully!")
            phase1_logger.info(f"Hostname changed to {newname}")
            return
        except Exception as e:
            phase1_logger.error(f"Error changing hostname: {e}")
            message_box(screen, f"Error: {e}")


def set_static_ip_form(screen):
    while True:
        interface = select_interface(screen)
        if interface is None:
            return

        while True:
            ip_address = input_box(screen, "Enter IP Address (e.g. 192.168.1.10):")
            if ip_address is None:
                return
            if not validate_ip(ip_address):
                message_box(screen, "Invalid IP address!")
                continue
            break

        while True:
            subnet_mask = input_box(screen, "Enter Subnet Mask in CIDR (0-32):")
            if subnet_mask is None:
                return
            if not subnet_mask.isdigit():
                message_box(screen, "Subnet mask must be a number.")
                continue
            mask_int = int(subnet_mask)
            if mask_int < 0 or mask_int > 32:
                message_box(screen, "Subnet mask out of range (0-32)!")
                continue
            break

        gateway = ""
        while True:
            gw = input_box(screen, "Enter Gateway IP (Optional):")
            if gw is None:
                return
            if gw == "":
                gateway = ""
                break
            if not validate_ip(gw):
                message_box(screen, "Invalid Gateway IP!")
                continue
            # Check if gateway is in same network
            try:
                network = ipaddress.ip_network(f"{ip_address}/{mask_int}", strict=False)
                if ipaddress.IPv4Address(gw) not in network:
                    message_box(screen, "Gateway not in same subnet!")
                    continue
            except:
                pass
            gateway = gw
            break

        perm = select_permanence(screen)
        if perm is None:
            return
        permanent = perm

        try:
            set_static_ip(interface, ip_address, mask_int, gateway, permanent)
            message_box(screen, "Static IP set successfully!")
            phase1_logger.info(
                f"Set static IP {ip_address}/{mask_int} on {interface}, permanent={permanent}"
            )
            return
        except Exception as e:
            phase1_logger.error(f"Error setting static IP: {e}")
            message_box(screen, f"Error: {e}")


def use_dhcp_form(screen):
    while True:
        iface = select_interface(screen)
        if iface is None:
            return
        try:
            use_dhcp(iface)
            message_box(screen, "DHCP enabled permanently!")
            phase1_logger.info(f"DHCP enabled on {iface}")
            return
        except Exception as e:
            phase1_logger.error(f"Error enabling DHCP: {e}")
            message_box(screen, f"Error: {e}")


def add_route_form(screen):
    while True:
        iface = select_interface(screen)
        if iface is None:
            return

        while True:
            dest_ip = input_box(screen, "Destination Network IP (e.g. 192.168.1.0):")
            if dest_ip is None:
                return
            if not validate_ip(dest_ip):
                message_box(screen, "Invalid Destination IP!")
                continue
            break

        while True:
            dest_mask = input_box(screen, "Enter Destination Network Mask (0-32):")
            if dest_mask is None:
                return
            if not dest_mask.isdigit():
                message_box(screen, "Subnet mask must be numeric!")
                continue
            dm = int(dest_mask)
            if dm < 0 or dm > 32:
                message_box(screen, "Invalid mask range (0-32).")
                continue
            break

        cidr = f"{dest_ip}/{dm}"

        while True:
            gw = input_box(screen, "Enter Gateway IP:")
            if gw is None:
                return
            if not validate_ip(gw):
                message_box(screen, "Invalid Gateway IP.")
                continue
            break

        perm = select_permanence(screen)
        if perm is None:
            return
        permanent = perm
        try:
            if permanent:
                add_route_permanent(iface, cidr, gw)
            else:
                add_route_temporary(iface, cidr, gw)
            message_box(screen, "Route added successfully!")
            phase1_logger.info(
                f"Added route {cidr} via {gw} on {iface}, perm={permanent}"
            )
            return
        except ValueError as ve:
            message_box(screen, str(ve))
        except subprocess.CalledProcessError as cpe:
            phase1_logger.error(f"Error adding route: {cpe}")
            message_box(screen, f"Error: {cpe}")


def remove_route_form(screen):
    while True:
        iface = select_interface(screen)
        if iface is None:
            return

        while True:
            dest_ip = input_box(screen, "Destination Network IP of route to remove:")
            if dest_ip is None:
                return
            if not validate_ip(dest_ip):
                message_box(screen, "Invalid Destination IP!")
                continue
            break

        while True:
            dest_mask = input_box(screen, "Enter Destination Network Mask (0-32):")
            if dest_mask is None:
                return
            if not dest_mask.isdigit():
                message_box(screen, "Subnet mask must be numeric!")
                continue
            dm = int(dest_mask)
            if dm < 0 or dm > 32:
                message_box(screen, "Invalid mask range!")
                continue
            break

        cidr = f"{dest_ip}/{dm}"

        while True:
            gw = input_box(screen, "Enter Gateway IP of route to remove:")
            if gw is None:
                return
            if not validate_ip(gw):
                message_box(screen, "Invalid Gateway IP.")
                continue
            break

        try:
            remove_route_temporary(iface, cidr, gw)
            message_box(screen, "Route removed successfully!")
            phase1_logger.info(f"Removed route {cidr} via {gw} on {iface}")
            return
        except ValueError as ve:
            message_box(screen, str(ve))
        except subprocess.CalledProcessError as cpe:
            phase1_logger.error(f"Error removing route: {cpe}")
            message_box(screen, f"Error: {cpe}")


def network_configuration_menu(screen):
    """
    Phase 1 menu for DNS, Hostname, Static IP, DHCP, Routes.
    """
    selected = 0
    options = [
        "Change DNS",
        "Change Hostname",
        "Set Static IP",
        "Use DHCP",
        "Add Route",
        "Remove Route",
        "Back to Main Menu",
    ]
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(
            screen,
            2,
            2,
            "Network Configuration Menu (ESC to go back)",
            screen.getmaxyx()[1] - 4,
        )
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + opt, screen.getmaxyx()[1] - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:
            if selected == 0:
                change_dns_form(screen)
            elif selected == 1:
                change_hostname_form(screen)
            elif selected == 2:
                set_static_ip_form(screen)
            elif selected == 3:
                use_dhcp_form(screen)
            elif selected == 4:
                add_route_form(screen)
            elif selected == 5:
                remove_route_form(screen)
            elif selected == 6:
                break
        elif key == 27:
            break


##################################
# Phase 2: Nftables Management   #
##################################


def flush_all_rules():
    """
    Flush all existing nftables rules (as a last resort).
    """
    try:
        subprocess.check_call(["nft", "flush", "ruleset"])
        phase2_logger.info("Flushed all nftables ruleset.")
    except Exception as e:
        phase2_logger.error(f"Failed to flush ruleset: {e}")


def remove_and_reinstall_nftables():
    """
    Remove and reinstall nftables completely.
    """
    try:
        run_command(["apt-get", "remove", "-y", "nftables"])
        run_command(["apt-get", "purge", "-y", "nftables"])
        run_command(["apt-get", "autoremove", "-y"])
        run_command(["apt-get", "install", "-y", "nftables"])
        phase2_logger.info("Successfully removed and reinstalled nftables.")
    except Exception as e:
        phase2_logger.error(f"Failed to remove/reinstall nftables: {e}")


def final_nft_attempt(screen):
    """
    After a flush or remove/reinstall attempt, do final tries to start service.
    """
    try:
        run_command(["systemctl", "enable", "nftables"])
        run_command(["systemctl", "start", "nftables"])
        phase2_logger.info("Finally started nftables.service after last resort.")
    except Exception as e:
        phase2_logger.error(f"Last resort attempt failed to start nftables: {e}")
        message_box(
            screen,
            "Could not start nftables even after last resort.\nRules will not apply properly.",
        )


def ensure_nftables_conf(screen):
    """
    Ensure /etc/nftables.conf has minimal definitions for 'inet filter'
    and 'ip nat'. If the file doesn't exist or is empty, create a default
    config. Adjust as needed for your environment.
    """
    conf_path = "/etc/nftables.conf"

    # If the file doesn't exist or is empty, create a basic config
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
            with open(conf_path, "w") as f:
                f.write(default_conf)
            # If you want to log success, do so here:
            # phase2_logger.info("Created a default /etc/nftables.conf with basic filter and nat config.")
        except Exception as e:
            # If there's a logging mechanism, you can log or show the error
            # For example:
            # phase2_logger.error(f"Error creating /etc/nftables.conf: {e}")
            # And possibly show a message to the user:
            message_box(screen, f"Error creating {conf_path}:\n{e}")


def check_nft_installed_phase2(screen):
    """
    Enhanced check for nft:
    1) which nft
    2) apt-get install if missing
    3) systemctl is-active ...
    4) if fails, flush all rules, remove & reinstall, final attempt
    """
    # 1) Check if nft is present
    have_nft = True
    try:
        subprocess.check_output(["which", "nft"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        message_box(screen, "nft command not found.\nAttempting to install nftables.")
        try:
            run_command(["apt-get", "update"])
            run_command(["apt-get", "install", "-y", "nftables"])
            phase2_logger.info("Successfully installed nftables.")
        except Exception as e:
            phase2_logger.error(f"Failed to install nftables: {e}")
            return False

    # 2) Check service
    try:
        status = subprocess.check_output(
            ["systemctl", "is-active", "nftables"], universal_newlines=True
        ).strip()
        if status != "active":
            # Try enable & start
            try:
                run_command(["systemctl", "enable", "nftables"])
                run_command(["systemctl", "start", "nftables"])
                phase2_logger.info("Enabled & started nftables.service.")
            except Exception as e:
                # Attempt flush + remove & reinstall
                phase2_logger.warning(
                    f"Failed to enable/start nftables.service initially:\n{e}"
                )
                flush_all_rules()
                remove_and_reinstall_nftables()
                final_nft_attempt(screen)
    except subprocess.CalledProcessError as se:
        # systemctl is-active failed
        phase2_logger.warning(f"systemctl is-active nftables failed: {se}")
        flush_all_rules()
        remove_and_reinstall_nftables()
        final_nft_attempt(screen)

    # 3) Ensure minimal config
    ensure_nftables_conf(screen)
    return True


def apply_nft_rule(screen, rule, nat=False):
    """
    Append rule to /etc/nftables.conf, then do `nft -f /etc/nftables.conf`.
    If nat=True, place the rule in ip nat postrouting/prerouting as needed.
    If nat=False, place it in inet filter input.
    """
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
        with open(conf_path, "a") as f:
            f.write(full_rule)

        run_command(["nft", "-f", conf_path])
        message_box(screen, "Rule added successfully!")
        phase2_logger.info(f"Added nftables rule: {full_rule.strip()}")
    except Exception as e:
        phase2_logger.error(f"Error applying nft rule: {e}")
        message_box(screen, f"Error applying rule:\n{e}")


###############
# RULE FORMS  #
###############


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
            continue


def ct_state_rule_form(screen):
    allowed_states = ["established", "related", "invalid", "new"]
    allowed_actions = ["accept", "drop", "reject"]

    state = input_box(screen, f"Enter ct state ({'/'.join(allowed_states)}):")
    if state is None:
        return
    while state not in allowed_states:
        message_box(screen, f"Invalid state: {state}")
        state = input_box(screen, f"Re-enter state ({'/'.join(allowed_states)}):")
        if state is None:
            return

    action = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if action is None:
        return
    while action not in allowed_actions:
        message_box(screen, f"Invalid action: {action}")
        action = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if action is None:
            return

    rule = f"ct state {state} {action}"
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
    action = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if action is None:
        return
    while action not in allowed_actions:
        message_box(screen, f"Invalid action: {action}")
        action = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if action is None:
            return

    rule = f"ip saddr {src} ip daddr {dst} {proto} dport {dport} {action}"
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
        icmp_type = input_box(
            screen, f"Re-enter ICMP type ({'/'.join(allowed_types)}):"
        )
        if icmp_type is None:
            return

    allowed_actions = ["accept", "drop"]
    action = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if action is None:
        return
    while action not in allowed_actions:
        message_box(screen, f"Invalid action: {action}")
        action = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if action is None:
            return

    rule = f"ip saddr {src} ip daddr {dst} icmp type {icmp_type} {action}"
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
    if ":" not in new_target:
        message_box(screen, "Invalid DNAT target format (use IP:PORT).")
        return
    ip_part, port_part = new_target.split(":", 1)
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


############################
# Phase 2 TUI Menu         #
############################


def nftables_menu(screen):
    if not check_nft_installed_phase2(screen):
        return  # If installation/enable fails, return quietly

    selected = 0
    options = [
        "Create ct_state rule",
        "Create IP-based rule",
        "Create ICMP rule",
        "Create masquerade rule",
        "Create DNAT rule",
        "Back to Main Menu",
    ]

    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(
            screen, 2, 2, "Phase 2: Nftables Management (ESC to go back)", max_x - 4
        )
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + opt, max_x - 4)

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


##################################
# Phase 3: OVS Utility Functions #
##################################


def run_cmd(cmd):
    """
    Run a shell command quietly, raise on failure.
    """
    with open(os.devnull, "w") as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)


def check_ovs_installed():
    """
    Check if OVS (ovs-vsctl) is installed on the system.
    If not, attempt to install 'openvswitch-switch' quietly.
    Returns True if installed or installed successfully, False if it fails.
    """
    try:
        # 'which ovs-vsctl' will raise CalledProcessError if not found
        subprocess.check_output(["which", "ovs-vsctl"], stderr=subprocess.STDOUT)
        # If we get here, OVS is already installed
        phase3_logger.info("OVS is already installed on this system.")
        return True
    except subprocess.CalledProcessError:
        # Not installed, let's install
        phase3_logger.info(
            "OVS is not installed. Attempting to install openvswitch-switch."
        )
        try:
            run_cmd(["apt-get", "update"])
            run_cmd(["apt-get", "install", "-y", "openvswitch-switch"])
            phase3_logger.info("Successfully installed openvswitch-switch.")
            return True
        except Exception as e:
            phase3_logger.error(f"Failed to install openvswitch-switch: {e}")
            return False


def bridge_exists(bridge_name):
    """
    Return True if an OVS bridge with 'bridge_name' already exists,
    otherwise False.
    Uses 'ovs-vsctl br-exists', which returns 0 if bridge exists,
    non-zero if not.
    """
    try:
        subprocess.check_call(["ovs-vsctl", "br-exists", bridge_name])
        return True  # if no error, bridge exists
    except subprocess.CalledProcessError:
        return False  # if error, means bridge doesn't exist


def interface_exists(iface_name):
    """
    Return True if network interface (port) 'iface_name' exists,
    otherwise False. Uses 'ip link show <iface_name>'.
    """
    try:
        subprocess.check_call(
            ["ip", "link", "show", iface_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


###############################
# Creating/Deleting Bridges   #
###############################


def add_ovs_bridge(bridge_name):
    """
    Create a new OVS bridge using 'ovs-vsctl add-br'.
    """
    run_cmd(["ovs-vsctl", "add-br", bridge_name])
    phase3_logger.info(f"Created OVS Bridge: {bridge_name}")


def delete_ovs_bridge(bridge_name):
    """
    Delete an OVS bridge if it exists, otherwise raise an error.
    """
    if not bridge_exists(bridge_name):
        phase3_logger.error(f"Bridge '{bridge_name}' does not exist.")
        raise ValueError(f"Bridge '{bridge_name}' does not exist.")

    run_cmd(["ovs-vsctl", "del-br", bridge_name])
    phase3_logger.info(f"Deleted OVS Bridge: {bridge_name}")


########################
# Adding/Removing Ports
########################


def add_port_to_bridge(bridge_name, port_name):
    """
    Add a port to an OVS bridge, checking if both bridge and port exist.
    If port doesn't exist (system interface), fail.
    For internal ports, user must specify 'type=internal' (see add_port_to_bridge_form).
    """
    if not bridge_exists(bridge_name):
        phase3_logger.error(f"Cannot add port to non-existent bridge '{bridge_name}'.")
        raise ValueError(f"Bridge '{bridge_name}' does not exist.")

    # If user said it's a system interface, we check if it exists
    # If it's an internal port, we skip - see add_port_to_bridge_form for logic
    # (In this function, we do not check again since we rely on the logic in the form.)

    # Just do it. If it fails, we catch the error above in the caller.
    run_cmd(["ovs-vsctl", "add-port", bridge_name, port_name])
    phase3_logger.info(f"Added port {port_name} to bridge {bridge_name}")


def remove_port_from_bridge(bridge_name, port_name):
    """
    Remove a port from a bridge. We rely on 'ovs-vsctl del-port' to fail if
    either the bridge or port doesn't exist or if the port is not on that bridge.
    """
    if not bridge_exists(bridge_name):
        phase3_logger.error(f"Bridge '{bridge_name}' does not exist.")
        raise ValueError(f"Bridge '{bridge_name}' does not exist.")

    # Attempt removal. If port isn't on the bridge, this fails,
    # and we catch the error in the caller.
    run_cmd(["ovs-vsctl", "del-port", bridge_name, port_name])
    phase3_logger.info(f"Removed port {port_name} from bridge {bridge_name}")


############################
# Up/Down, Trunk/Access
############################


def bring_port_up(port_name):
    """
    Bring a port up: 'ip link set <port> up'.
    """
    run_cmd(["ip", "link", "set", port_name, "up"])
    phase3_logger.info(f"Brought port {port_name} up")


def bring_port_down(port_name):
    """
    Bring a port down: 'ip link set <port> down'.
    """
    run_cmd(["ip", "link", "set", port_name, "down"])
    phase3_logger.info(f"Brought port {port_name} down")


def set_port_trunk(port_name, vlan_list):
    """
    Switch port to trunk mode by removing 'tag' and setting 'trunks'.
    Example: trunks=10,20,30
    """
    # First remove 'tag' if any
    run_cmd(["ovs-vsctl", "remove", "port", port_name, "tag"])
    # Then set trunk
    run_cmd(["ovs-vsctl", "set", "port", port_name, f"trunks={vlan_list}"])
    phase3_logger.info(f"Set port {port_name} as trunk with VLANs: {vlan_list}")


def set_port_access(port_name, vlan_id):
    """
    Switch port to access mode by removing 'trunks' config and setting 'tag'.
    Now uses '--if-exists remove' to avoid non-zero exit if no trunk existed.
    """
    run_cmd(["ovs-vsctl", "--if-exists", "remove", "port", port_name, "trunks"])
    run_cmd(["ovs-vsctl", "set", "port", port_name, f"tag={vlan_id}"])
    phase3_logger.info(f"Set port {port_name} as access on VLAN {vlan_id}")


def configure_ip_on_vlan_interface(vlan_interface, ip_address, subnet_mask):
    """
    Validate that 'vlan_interface' exists, then assign IP with 'ip' commands.
    """
    try:
        subprocess.check_call(["ip", "link", "show", vlan_interface])
    except subprocess.CalledProcessError:
        phase3_logger.error(f"VLAN interface '{vlan_interface}' not found.")
        raise ValueError(f"VLAN interface '{vlan_interface}' does not exist.")

    cidr = f"{ip_address}/{subnet_mask}"
    run_cmd(["ip", "addr", "flush", "dev", vlan_interface])
    run_cmd(["ip", "addr", "add", cidr, "dev", vlan_interface])
    run_cmd(["ip", "link", "set", vlan_interface, "up"])
    phase3_logger.info(f"Configured {vlan_interface} with IP {cidr}")


#######################
# Phase 3 TUI Menus   #
#######################


def add_ovs_bridge_form(screen):
    """
    Ask user for a bridge name, then create it if it doesn't exist.
    """
    br = input_box(screen, "Enter new OVS bridge name:")
    if br is None:
        return
    # 1. Check if bridge already exists:
    if bridge_exists(br):
        message_box(
            screen, f"Bridge '{br}' already exists!\nPlease choose another name."
        )
        phase3_logger.warning(f"Attempted to create existing bridge '{br}'.")
        return
    # 2. Create if doesn't exist
    try:
        add_ovs_bridge(br)
        message_box(screen, f"Created OVS bridge '{br}' successfully!")
    except Exception as e:
        phase3_logger.error(f"Error creating bridge {br}: {e}")
        message_box(screen, f"Error creating bridge:\n{e}")


def delete_ovs_bridge_form(screen):
    """
    Ask user for a bridge name, delete it.
    """
    br = input_box(screen, "Enter OVS bridge name to delete:")
    if br is None:
        return
    try:
        delete_ovs_bridge(br)
        message_box(screen, f"Deleted OVS bridge '{br}' successfully!")
    except Exception as e:
        phase3_logger.error(f"Error deleting bridge {br}: {e}")
        message_box(screen, f"Error deleting bridge:\n{e}")


def select_port_type(screen):
    """
    Ask user if the new port is a system interface or an internal port.
    Returns "system" or "internal", or None if user goes back.
    """
    options = ["System Port (already exists)", "OVS Internal Port", "Back"]
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Choose Port Type (ESC to go back)", max_x - 4)
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + opt, max_x - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:  # Enter
            if options[selected] == "Back":
                return None
            elif options[selected].startswith("System"):
                return "system"
            elif options[selected].startswith("OVS Internal"):
                return "internal"
        elif key == 27:  # ESC
            return None


def add_port_to_bridge_form(screen):
    """
    Ask user for a bridge, then ask for port name,
    then ask if it's system or internal,
    and add accordingly.
    """
    br = input_box(screen, "Enter OVS bridge name:")
    if br is None:
        return

    port_name = input_box(screen, "Enter port (interface) name to add:")
    if port_name is None:
        return

    port_type = select_port_type(screen)  # system or internal
    if port_type is None:
        return

    try:
        if not bridge_exists(br):
            message_box(screen, f"Bridge '{br}' does not exist!")
            phase3_logger.warning(
                f"User tried to add port to non-existent bridge '{br}'."
            )
            return

        if port_type == "system":
            # Check if underlying interface actually exists
            if not interface_exists(port_name):
                message_box(
                    screen,
                    f"Interface '{port_name}' does not exist!\nCannot add to OVS as a system port.",
                )
                phase3_logger.warning(
                    f"User tried adding non-existent system interface '{port_name}' to {br}."
                )
                return
            # Add an existing system interface
            run_cmd(["ovs-vsctl", "add-port", br, port_name])
            phase3_logger.info(
                f"Added existing system port '{port_name}' to bridge '{br}'"
            )
        else:
            # internal
            # Creating an OVS internal port that does not exist yet
            run_cmd(
                [
                    "ovs-vsctl",
                    "add-port",
                    br,
                    port_name,
                    "--",
                    "set",
                    "interface",
                    port_name,
                    "type=internal",
                ]
            )
            phase3_logger.info(f"Created internal port '{port_name}' on bridge '{br}'")

        message_box(
            screen, f"Port '{port_name}' added to bridge '{br}' as {port_type}."
        )
    except Exception as e:
        phase3_logger.error(
            f"Error adding port {port_name} to {br} as {port_type}: {e}"
        )
        message_box(screen, f"Error adding port:\n{e}")


def remove_port_from_bridge_form(screen):
    """
    Ask user for bridge, port to remove.
    """
    br = input_box(screen, "Enter OVS bridge name:")
    if br is None:
        return
    prt = input_box(screen, "Enter port name to remove from bridge:")
    if prt is None:
        return
    try:
        remove_port_from_bridge(br, prt)
        message_box(screen, f"Removed port '{prt}' from bridge '{br}'.")
    except Exception as e:
        phase3_logger.error(f"Error removing port {prt} from bridge {br}: {e}")
        message_box(screen, f"Error removing port:\n{e}")


def bring_port_up_form(screen):
    prt = input_box(screen, "Enter port (interface) name to bring up:")
    if prt is None:
        return
    # Check if port actually exists:
    if not interface_exists(prt):
        message_box(screen, f"Interface '{prt}' does not exist!\nCannot bring it up.")
        phase3_logger.warning(f"User tried to bring up non-existent port '{prt}'.")
        return
    try:
        bring_port_up(prt)
        message_box(screen, f"Port '{prt}' is now up.")
    except Exception as e:
        phase3_logger.error(f"Error bringing port {prt} up: {e}")
        message_box(screen, f"Error:\n{e}")


def bring_port_down_form(screen):
    prt = input_box(screen, "Enter port (interface) name to bring down:")
    if prt is None:
        return
    # Check if port actually exists:
    if not interface_exists(prt):
        message_box(screen, f"Interface '{prt}' does not exist!\nCannot bring it down.")
        phase3_logger.warning(f"User tried to bring down non-existent port '{prt}'.")
        return
    try:
        bring_port_down(prt)
        message_box(screen, f"Port '{prt}' is now down.")
    except Exception as e:
        phase3_logger.error(f"Error bringing port {prt} down: {e}")
        message_box(screen, f"Error:\n{e}")


def set_port_trunk_form(screen):
    prt = input_box(screen, "Enter port name to set as trunk:")
    if prt is None:
        return
    if not interface_exists(prt):
        message_box(
            screen, f"Interface '{prt}' does not exist!\nCannot set trunk mode."
        )
        phase3_logger.warning(f"Attempted trunk on non-existent port '{prt}'.")
        return
    vlans = input_box(screen, "Enter comma-separated VLAN IDs (e.g. 10,20,30):")
    if vlans is None:
        return
    try:
        set_port_trunk(prt, vlans)
        message_box(screen, f"Set port '{prt}' trunk with VLANs '{vlans}'.")
    except Exception as e:
        phase3_logger.error(f"Error setting trunk mode on {prt}: {e}")
        message_box(screen, f"Error:\n{e}")


def set_port_access_form(screen):
    prt = input_box(screen, "Enter port name to set as access:")
    if prt is None:
        return
    if not interface_exists(prt):
        message_box(
            screen, f"Interface '{prt}' does not exist!\nCannot set access mode."
        )
        phase3_logger.warning(f"Attempted access mode on non-existent port '{prt}'.")
        return
    vlan_id_str = input_box(screen, "Enter single VLAN ID (e.g. 10):")
    if vlan_id_str is None:
        return
    if not vlan_id_str.isdigit():
        message_box(screen, "VLAN ID must be numeric!")
        return
    try:
        set_port_access(prt, vlan_id_str)
        message_box(screen, f"Set port '{prt}' as access on VLAN {vlan_id_str}.")
    except Exception as e:
        phase3_logger.error(f"Error setting access mode on {prt}: {e}")
        message_box(screen, f"Error:\n{e}")


def configure_ip_for_vlan_interface_form(screen):
    """
    Ask user for the VLAN interface name, IP, and subnet mask.
    Then call configure_ip_on_vlan_interface.
    """
    vlan_if = input_box(screen, "Enter VLAN interface name (e.g. vlan10 or br0.10):")
    if vlan_if is None:
        return

    ip_str = input_box(screen, "Enter IP Address (e.g. 192.168.10.5):")
    if ip_str is None:
        return
    try:
        ipaddress.IPv4Address(ip_str)
    except:
        message_box(screen, "Invalid IP address!")
        return

    mask_str = input_box(screen, "Enter Subnet Mask in CIDR (0-32):")
    if mask_str is None:
        return
    if not mask_str.isdigit():
        message_box(screen, "Mask must be numeric.")
        return
    mask_int = int(mask_str)
    if mask_int < 0 or mask_int > 32:
        message_box(screen, "Mask out of range (0-32)!")
        return

    try:
        configure_ip_on_vlan_interface(vlan_if, ip_str, mask_int)
        message_box(
            screen, f"Configured VLAN interface '{vlan_if}' with {ip_str}/{mask_int}."
        )
    except Exception as e:
        phase3_logger.error(f"Error configuring IP on VLAN interface {vlan_if}: {e}")
        message_box(screen, f"Error:\n{e}")


######################
# Phase 3 TUI Menu   #
######################


def ovs_management_menu(screen):
    """
    Phase 3 TUI for OVS management.
    """
    # 1) Check if OVS installed
    if not check_ovs_installed():
        message_box(
            screen,
            "Failed to install Open vSwitch.\nCannot proceed with OVS management.",
        )
        return

    selected = 0
    options = [
        "Add OVS Bridge",
        "Delete OVS Bridge",
        "Add Port to Bridge",
        "Remove Port from Bridge",
        "Bring Port Up",
        "Bring Port Down",
        "Set Port as Trunk",
        "Set Port as Access",
        "Configure IP for VLAN Interface",
        "Back to Main Menu",
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(
            screen, 2, 2, "Phase 3: Open vSwitch Management (ESC to go back)", max_x - 4
        )

        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + opt, max_x - 4)

        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in (10, 13):
            if selected == 0:
                add_ovs_bridge_form(screen)
            elif selected == 1:
                delete_ovs_bridge_form(screen)
            elif selected == 2:
                add_port_to_bridge_form(screen)
            elif selected == 3:
                remove_port_from_bridge_form(screen)
            elif selected == 4:
                bring_port_up_form(screen)
            elif selected == 5:
                bring_port_down_form(screen)
            elif selected == 6:
                set_port_trunk_form(screen)
            elif selected == 7:
                set_port_access_form(screen)
            elif selected == 8:
                configure_ip_for_vlan_interface_form(screen)
            elif selected == 9:
                break
        elif key == 27:
            break


##############################
# Phase 4: Network Monitoring
##############################


def get_interfaces():
    """
    Return a list of network interfaces on the system by reading /sys/class/net.
    """
    return os.listdir("/sys/class/net")


def interface_is_up(iface):
    """
    Return True if 'iface' is UP, False otherwise, by checking 'cat /sys/class/net/iface/operstate'.
    """
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r") as f:
            state = f.read().strip()
            return state == "up"
    except Exception as e:
        phase4_logger.error(f"Error reading state for {iface}: {e}")
        return False


def get_interface_type(iface):
    """
    Guess interface type: physical or virtual.
    A simple approach: if /sys/class/net/<iface>/device exists, assume physical.
    If not, assume virtual.
    """
    dev_path = f"/sys/class/net/{iface}/device"
    if os.path.exists(dev_path):
        return "physical"
    else:
        return "virtual"


def get_link_speed(iface):
    """
    Attempt to read link speed from /sys/class/net/<iface>/speed (some drivers support this).
    If not supported, return 'unknown'.
    """
    speed_path = f"/sys/class/net/{iface}/speed"
    if os.path.exists(speed_path):
        try:
            with open(speed_path, "r") as f:
                speed_val = f.read().strip()
                return speed_val + " Mb/s"
        except Exception as e:
            phase4_logger.warning(f"Cannot read link speed for {iface}: {e}")
            return "unknown"
    return "unknown"


def get_ip_addresses(iface):
    """
    Return a list of IP addresses (v4) assigned to 'iface' using 'ip -4 addr show <iface>'.
    """
    ips = []
    try:
        output = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], universal_newlines=True
        )
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                # example: 'inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic noprefixroute ens33'
                parts = line.split()
                if len(parts) >= 2:
                    ip_cidr = parts[1]  # e.g. 192.168.1.10/24
                    ips.append(ip_cidr)
    except subprocess.CalledProcessError as cpe:
        phase4_logger.error(f"Error reading IP addresses for {iface}: {cpe}")
    return ips


def get_protocol_stats():
    """
    Return a dict of TCP/UDP stats from /proc/net/snmp or 'ss' command.
    For simplicity, we parse /proc/net/snmp for basic 'Tcp:' and 'Udp:' lines.
    """
    stats = {
        "tcp_established": 0,
        "tcp_listen": 0,
        "udp_in_datagrams": 0,
        "udp_out_datagrams": 0,
    }
    # Attempt to parse /proc/net/snmp
    try:
        with open("/proc/net/snmp", "r") as f:
            for line in f:
                line = line.strip()
                # For TCP line might be: "Tcp: RtoAlgorithm RtoMin RtoMax ..."
                if line.startswith("Tcp:"):
                    # read the next line for actual values? or parse the same line?
                    # Actually /proc/net/snmp has two lines for each protocol:
                    #   - a header
                    #   - a data line
                    pass
        # Alternatively, use 'ss -t -a' to count established or 'ss -u' for UDP, etc.
        # We'll do a simpler approach using 'ss' below
    except Exception as e:
        phase4_logger.error(f"Error reading /proc/net/snmp: {e}")

    # We'll do a quick approach with 'ss':
    try:
        # count tcp established
        tcp_est_out = subprocess.check_output(
            ["ss", "-t", "-a", "-n", "state", "established"], universal_newlines=True
        )
        # first line is a header, subsequent lines are connections
        lines = tcp_est_out.strip().split("\n")
        if len(lines) > 1:
            stats["tcp_established"] = len(lines) - 1
    except subprocess.CalledProcessError:
        pass
    # count tcp listening
    try:
        tcp_listen_out = subprocess.check_output(
            ["ss", "-t", "-a", "-n", "state", "listening"], universal_newlines=True
        )
        lines = tcp_listen_out.strip().split("\n")
        if len(lines) > 1:
            stats["tcp_listen"] = len(lines) - 1
    except subprocess.CalledProcessError:
        pass
    # for UDP, let's just do 'ss -u -a'
    try:
        udp_out = subprocess.check_output(
            ["ss", "-u", "-a", "-n"], universal_newlines=True
        )
        lines = udp_out.strip().split("\n")
        if len(lines) > 1:
            # This is a simplistic measure of open UDP sockets
            stats["udp_in_datagrams"] = len(lines) - 1
    except subprocess.CalledProcessError:
        pass

    return stats


def get_bytes_packets(iface):
    """
    Return (rx_bytes, rx_packets, tx_bytes, tx_packets) for 'iface'
    from /sys/class/net/<iface>/statistics.
    """
    base_path = f"/sys/class/net/{iface}/statistics"
    try:
        with open(os.path.join(base_path, "rx_bytes"), "r") as f:
            rx_b = int(f.read().strip())
        with open(os.path.join(base_path, "rx_packets"), "r") as f:
            rx_p = int(f.read().strip())
        with open(os.path.join(base_path, "tx_bytes"), "r") as f:
            tx_b = int(f.read().strip())
        with open(os.path.join(base_path, "tx_packets"), "r") as f:
            tx_p = int(f.read().strip())
        return (rx_b, rx_p, tx_b, tx_p)
    except Exception as e:
        phase4_logger.error(f"Error reading stats for {iface}: {e}")
        return (0, 0, 0, 0)


#################################
# TUI: Phase 4 Monitoring Menu  #
#################################


def view_interface_info(screen):
    """
    Display name, status, type, link speed, and IP addresses for each interface.
    """
    interfaces = get_interfaces()
    screen.clear()
    screen.border(0)
    max_y, max_x = screen.getmaxyx()
    print_wrapped(
        screen, 1, 2, "Interfaces Information (Press any key to return)", max_x - 4
    )
    y = 3
    for iface in interfaces:
        up_down = "UP" if interface_is_up(iface) else "DOWN"
        iface_type = get_interface_type(iface)
        speed = get_link_speed(iface)
        ips = get_ip_addresses(iface)

        line1 = f"{iface:10s}  {up_down:4s}  {iface_type:8s}  {speed:8s}"
        print_wrapped(screen, y, 2, line1, max_x - 4)
        y += 1
        if ips:
            for ipaddr in ips:
                print_wrapped(screen, y, 4, f"IP: {ipaddr}", max_x - 6)
                y += 1
        else:
            print_wrapped(screen, y, 4, "No IPv4 assigned", max_x - 6)
            y += 1
        y += 1
        if y >= max_y - 1:
            break

    screen.refresh()
    screen.getch()  # Wait for user to press a key


def view_protocol_stats(screen):
    """
    Display stats about TCP/UDP using get_protocol_stats.
    """
    stats = get_protocol_stats()
    screen.clear()
    screen.border(0)
    max_y, max_x = screen.getmaxyx()
    line1 = "Network Protocol Statistics"
    print_wrapped(screen, 1, 2, line1, max_x - 4)
    y = 3
    print_wrapped(
        screen, y, 2, f"TCP Established: {stats['tcp_established']}", max_x - 4
    )
    y += 1
    print_wrapped(screen, y, 2, f"TCP Listening:   {stats['tcp_listen']}", max_x - 4)
    y += 2
    # 'udp_in_datagrams' is just how many open sockets we found from 'ss -u'
    print_wrapped(
        screen, y, 2, f"UDP Sockets Found: {stats['udp_in_datagrams']}", max_x - 4
    )
    y += 2
    print_wrapped(screen, y, 2, "(Press any key to return)", max_x - 4)

    screen.refresh()
    screen.getch()


def view_bytes_packets_info(screen):
    """
    Show number of bytes and packets for each interface (not real-time).
    """
    interfaces = get_interfaces()
    screen.clear()
    screen.border(0)
    max_y, max_x = screen.getmaxyx()
    print_wrapped(
        screen,
        1,
        2,
        "Interface Traffic Statistics (Press any key to return)",
        max_x - 4,
    )
    y = 3
    for iface in interfaces:
        rx_b, rx_p, tx_b, tx_p = get_bytes_packets(iface)
        line = f"{iface:10s}  RX_Bytes={rx_b}  RX_Pkts={rx_p}  TX_Bytes={tx_b}  TX_Pkts={tx_p}"
        print_wrapped(screen, y, 2, line, max_x - 4)
        y += 1
        if y >= max_y - 1:
            break
    screen.refresh()
    screen.getch()


def view_realtime_bandwidth(screen):
    """
    Show real-time bandwidth usage for each interface by sampling stats over 1-second intervals.
    Press 'q' to exit.
    """
    interfaces = get_interfaces()
    # We'll store previous RX/TX bytes in a dict
    prev_stats = {}
    for iface in interfaces:
        rx_b, _, tx_b, _ = get_bytes_packets(iface)
        prev_stats[iface] = (rx_b, tx_b)

    screen.nodelay(True)  # non-blocking getch
    max_y, max_x = screen.getmaxyx()

    try:
        while True:
            # Check if user pressed 'q'
            c = screen.getch()
            if c == ord("q") or c == ord("Q"):
                break

            screen.clear()
            screen.border(0)
            print_wrapped(
                screen, 1, 2, "Real-time Bandwidth (press 'q' to quit)", max_x - 4
            )
            y = 3

            for iface in interfaces:
                rx_b, _, tx_b, _ = get_bytes_packets(iface)
                (old_rx, old_tx) = prev_stats.get(iface, (rx_b, tx_b))

                # bytes difference over 1 second = bytes/s
                rx_rate = rx_b - old_rx
                tx_rate = tx_b - old_tx

                # Update
                prev_stats[iface] = (rx_b, tx_b)

                line = f"{iface:10s} RX={rx_rate} B/s  TX={tx_rate} B/s"
                print_wrapped(screen, y, 2, line, max_x - 4)
                y += 1
                if y >= max_y - 1:
                    break

            screen.refresh()
            time.sleep(1.0)  # 1-second interval
    except Exception as e:
        phase4_logger.error(f"Error in real-time bandwidth monitor: {e}")
        message_box(screen, f"Error:\n{e}")
    finally:
        screen.nodelay(False)


def network_monitoring_menu(screen):
    """
    Phase 4: Network Monitoring TUI
    """
    selected = 0
    options = [
        "View Network Interfaces Information",
        "View Network Bandwidth in Real-time",
        "View Network Protocol Statistics (TCP/UDP)",
        "View Bytes/Packets for Interfaces",
        "Back to Main Menu",
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(
            screen,
            2,
            2,
            "Network Monitoring Dashboard Menu (ESC to go back)",
            max_x - 4,
        )

        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + opt, max_x - 4)

        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in (10, 13):
            if selected == 0:
                view_interface_info(screen)
            elif selected == 1:
                view_realtime_bandwidth(screen)
            elif selected == 2:
                view_protocol_stats(screen)
            elif selected == 3:
                view_bytes_packets_info(screen)
            elif selected == 4:
                break
        elif key == 27:
            break


###############################
# Main Menu (Phases 1 & 2 & 3 & 4)
###############################


def main_menu(screen):
    selected = 0
    options = [
        "Network Configuration",  # Phase 1
        "Nftables Management",  # Phase 2
        "Open vSwitch Management",  # Phase 3
        "Network Monitoring",  # Phase 4
        "Exit",
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Main Menu (ESC to exit)", max_x - 4)
        for idx, opt in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + opt, max_x - 4)

        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:
            if selected == 0:
                # Phase 1: network_configuration_menu(screen)
                network_configuration_menu(screen)
            elif selected == 1:
                # Phase 2: nftables_menu(screen)
                nftables_menu(screen)
            elif selected == 2:
                # Phase 3: OVS management
                ovs_management_menu(screen)
            elif selected == 3:
                # Phase 4: Network Monitoring
                network_monitoring_menu(screen)
            elif selected == 4:
                break
        elif key == 27:  # ESC
            break


def main(screen):
    if os.geteuid() != 0:
        screen.clear()
        screen.border(0)
        message_box(screen, "Error: Must run as root.\nPress any key to exit.")
        return
    main_menu(screen)


if __name__ == "__main__":
    curses.wrapper(main)
