import curses
import logging
import ipaddress
import os
import subprocess

########################################
# Common Helper Functions and Utilities #
########################################

def print_wrapped(screen, start_y, start_x, text, max_width):
    """
    Print text at (start_y, start_x), truncating if it exceeds max_width.
    Helps maintain layout in limited terminal widths.
    """
    if len(text) > max_width:
        text = text[:max_width-1]
    screen.addstr(start_y, start_x, text)

def message_box(screen, message):
    """
    Display a boxed message. The user presses any key to continue.
    Useful for errors, confirmations, and notifications.
    """
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
    """
    Display a prompt and allow text input.
    Press ESC or type 'back' to return None, allowing user to go back from this step.
    """
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
    print_wrapped(screen, y+1, 2, "(Press ESC or type 'back' to return)", max_x - 4)

    input_y = y + 3
    input_x = 2
    screen.move(input_y, input_x)
    screen.refresh()

    buffer = []
    curses.curs_set(1)
    while True:
        ch = screen.getch()
        if ch == 27:  # ESC key
            curses.curs_set(0)
            return None
        elif ch == curses.KEY_BACKSPACE or ch == 127:
            # Handle backspace
            if buffer:
                buffer.pop()
                screen.delch(input_y, input_x + len(buffer))
        elif ch == 10:  # Enter key
            user_input = "".join(buffer).strip()
            curses.curs_set(0)
            if user_input.lower() == "back":
                return None
            return user_input
        elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_UP, curses.KEY_DOWN):
            continue
        else:
            if 32 <= ch <= 126:  # Printable chars
                buffer.append(chr(ch))
                screen.addch(input_y, input_x + len(buffer)-1, ch)

def select_interface(screen):
    """
    Display a list of interfaces. User can select one or press ESC to go back.
    Returns chosen interface or None.
    """
    interfaces = get_network_interfaces()
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(screen, 2, 2, "Select Interface (ESC to go back)", screen.getmaxyx()[1]-4)
        for idx, iface in enumerate(interfaces):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + iface, screen.getmaxyx()[1]-4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(interfaces) - 1:
            selected += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            return interfaces[selected]
        elif key == 27:
            return None

def select_permanence(screen):
    """
    Ask user if changes should be Temporary or Permanent.
    Also has 'Back' option to cancel.
    Returns True if permanent, False if temporary, None if back.
    """
    options = ["Temporarily", "Permanently", "Back"]
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(screen, 2, 2, "Apply Change:", screen.getmaxyx()[1]-4)
        for idx, option in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + option, screen.getmaxyx()[1]-4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            if options[selected] == "Back":
                return None
            return (selected == 1)  # True if permanent
        elif key == 27:
            return None

def get_network_interfaces():
    """
    Return a list of network interfaces by listing /sys/class/net.
    """
    return os.listdir('/sys/class/net/')

def run_command(cmd):
    """
    Run a shell command silently, raising CalledProcessError on failure.
    """
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)

def validate_ip(ip_str):
    """
    Validate if ip_str is a correct IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except:
        return False

def route_exists(destination_cidr, gateway, interface_name):
    """
    Check if a given route exists in the system's routing table.
    """
    output = subprocess.check_output(['ip', 'route', 'show'], universal_newlines=True)
    route_line = f"{destination_cidr} via {gateway} dev {interface_name}"
    return route_line in output

########################################
# Phase 1: Network Configuration       #
########################################

def add_route_temporary(interface_name, destination_cidr, gateway):
    cmd = ['ip', 'route', 'add', destination_cidr, 'via', gateway, 'dev', interface_name]
    subprocess.check_call(cmd)
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after addition, something went wrong.")

def add_route_permanent(interface_name, destination_cidr, gateway):
    try:
        run_command(['nmcli', 'connection', 'modify', interface_name, '+ipv4.routes', f"{destination_cidr} {gateway}"])
        run_command(['nmcli', 'connection', 'up', interface_name])
    except subprocess.CalledProcessError as e:
        raise e
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after permanent addition, something went wrong.")

def remove_route_temporary(interface_name, destination_cidr, gateway):
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route does not exist.")
    cmd = ['ip', 'route', 'del', destination_cidr, 'via', gateway, 'dev', interface_name]
    subprocess.check_call(cmd)

def change_dns(interface_name, dns_list, permanent):
    if permanent:
        run_command(['nmcli', 'connection', 'modify', interface_name, 'ipv4.dns', ','.join(dns_list)])
        run_command(['nmcli', 'connection', 'up', interface_name])
    else:
        for dns in dns_list:
            run_command(['resolvectl', 'dns', interface_name, dns])

def change_hostname(new_hostname):
    run_command(['hostnamectl', 'set-hostname', new_hostname])

def set_static_ip(interface_name, ip_address, subnet_mask, gateway, permanent):
    cidr = f"{ip_address}/{subnet_mask}"
    if permanent:
        run_command(['nmcli', 'connection', 'modify', interface_name, 'ipv4.addresses', cidr])
        if gateway:
            run_command(['nmcli', 'connection', 'modify', interface_name, 'ipv4.gateway', gateway])
        run_command(['nmcli', 'connection', 'modify', interface_name, 'ipv4.method', 'manual'])
        run_command(['nmcli', 'connection', 'up', interface_name])
    else:
        run_command(['ip', 'addr', 'flush', 'dev', interface_name])
        run_command(['ip', 'addr', 'add', cidr, 'dev', interface_name])
        if gateway:
            run_command(['ip', 'route', 'add', 'default', 'via', gateway, 'dev', interface_name])

def use_dhcp(interface_name):
    run_command(['nmcli', 'connection', 'modify', interface_name, 'ipv4.method', 'auto'])
    run_command(['nmcli', 'connection', 'up', interface_name])

##############################
# Phase 1 Menu               #
###############################

def change_dns_form(screen):
    """
    Form to change DNS servers either temporarily or permanently.
    """
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        while True:
            dns_servers = input_box(screen, "Enter up to 3 DNS Servers (comma-separated):")
            if dns_servers is None:
                break
            if dns_servers == '':
                message_box(screen, "DNS Servers cannot be empty!")
                continue
            dns_list = [dns.strip() for dns in dns_servers.split(',') if dns.strip()]
            if len(dns_list) == 0:
                message_box(screen, "No valid DNS servers entered!")
                continue
            if len(dns_list) > 3:
                message_box(screen, "More than 3 DNS servers entered, please enter up to 3.")
                continue
            valid_dns = True
            for dns in dns_list:
                if not validate_ip(dns):
                    message_box(screen, f"Invalid DNS Server IP: {dns}")
                    valid_dns = False
                    break
            if not valid_dns:
                continue

            p = select_permanence(screen)
            if p is None:
                break
            permanent = p
            try:
                change_dns(interface, dns_list, permanent)
                message_box(screen, "DNS Servers updated successfully!")
                logging.info(f"DNS updated to {dns_list} on {interface}, permanent={permanent}")
                return
            except Exception as e:
                logging.error(f"Error updating DNS: {e}")
                message_box(screen, f"Error: {e}")
        return

def change_hostname_form(screen):
    """
    Form to change system hostname.
    """
    while True:
        hostname = input_box(screen, "Enter New Hostname:")
        if hostname is None:
            return
        if not hostname:
            message_box(screen, "Hostname cannot be empty!")
            continue
        try:
            change_hostname(hostname)
            message_box(screen, "Hostname changed successfully!")
            logging.info(f"Hostname changed to {hostname}")
            return
        except Exception as e:
            logging.error(f"Error changing hostname: {e}")
            message_box(screen, f"Error: {e}")

def set_static_ip_form(screen):
    """
    Form to set a static IP address on an interface.
    """
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        # IP address
        while True:
            ip_address = input_box(screen, "Enter IP Address (e.g. 192.168.1.10):")
            if ip_address is None:
                return
            if not validate_ip(ip_address):
                message_box(screen, "Invalid IP Address!")
                continue
            break
        # Subnet mask
        while True:
            subnet_mask = input_box(screen, "Enter Subnet Mask in CIDR (0-32):")
            if subnet_mask is None:
                return
            if not subnet_mask.isdigit():
                message_box(screen, "Subnet mask must be a number!")
                continue
            mask_int = int(subnet_mask)
            if mask_int < 0 or mask_int > 32:
                message_box(screen, "Subnet mask out of range (0-32)!")
                continue
            break
        # Gateway (optional)
        while True:
            gw_input = input_box(screen, "Enter Gateway IP (Optional):")
            if gw_input is None:
                return
            if gw_input == '':
                gateway = ''
                break
            if not validate_ip(gw_input):
                message_box(screen, "Invalid Gateway IP!")
                continue
            try:
                network = ipaddress.ip_network(f"{ip_address}/{mask_int}", strict=False)
                if ipaddress.IPv4Address(gw_input) not in network:
                    message_box(screen, "Gateway not in the same subnet!")
                    continue
            except:
                pass
            gateway = gw_input
            break

        p = select_permanence(screen)
        if p is None:
            return
        permanent = p
        try:
            set_static_ip(interface, ip_address, mask_int, gateway, permanent)
            message_box(screen, "Static IP set successfully!")
            logging.info(f"Static IP {ip_address}/{mask_int} set on {interface}, permanent={permanent}")
            return
        except Exception as e:
            logging.error(f"Error setting static IP: {e}")
            message_box(screen, f"Error: {e}")

def use_dhcp_form(screen):
    """
    Form to enable DHCP permanently on an interface.
    """
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        try:
            use_dhcp(interface)
            message_box(screen, "DHCP enabled successfully (permanent)!")
            logging.info(f"DHCP enabled on {interface} permanently")
            return
        except Exception as e:
            logging.error(f"Error enabling DHCP: {e}")
            message_box(screen, f"Error: {e}")

def add_route_form(screen):
    """
    Form to add a route (temporary or permanent).
    """
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        # Destination IP
        while True:
            dest_ip = input_box(screen, "Enter Destination Network IP (e.g. 192.168.1.0):")
            if dest_ip is None:
                return
            if not validate_ip(dest_ip):
                message_box(screen, "Invalid Destination IP!")
                continue
            break
        # Subnet mask
        while True:
            dest_mask = input_box(screen, "Enter Destination Network Mask (0-32):")
            if dest_mask is None:
                return
            if not dest_mask.isdigit():
                message_box(screen, "Subnet mask must be a number!")
                continue
            dest_mask_int = int(dest_mask)
            if dest_mask_int < 0 or dest_mask_int > 32:
                message_box(screen, "Invalid subnet mask range!")
                continue
            break
        destination_cidr = f"{dest_ip}/{dest_mask_int}"
        # Gateway
        while True:
            gateway = input_box(screen, "Enter Gateway IP:")
            if gateway is None:
                return
            if not validate_ip(gateway):
                message_box(screen, "Invalid Gateway IP!")
                continue
            break
        p = select_permanence(screen)
        if p is None:
            return
        permanent = p
        try:
            if permanent:
                add_route_permanent(interface, destination_cidr, gateway)
            else:
                add_route_temporary(interface, destination_cidr, gateway)
            message_box(screen, "Route added successfully!")
            logging.info(f"Route {destination_cidr} via {gateway} on {interface}, perm={permanent}")
            return
        except ValueError as ve:
            message_box(screen, f"{ve}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error adding route: {e}")
            message_box(screen, f"Error: {e}")

def remove_route_form(screen):
    """
    Form to remove a route temporarily.
    """
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        # Destination IP
        while True:
            dest_ip = input_box(screen, "Enter Destination Network IP of route to remove:")
            if dest_ip is None:
                return
            if not validate_ip(dest_ip):
                message_box(screen, "Invalid Destination IP!")
                continue
            break
        # Subnet mask
        while True:
            dest_mask = input_box(screen, "Enter Destination Network Mask (0-32):")
            if dest_mask is None:
                return
            if not dest_mask.isdigit():
                message_box(screen, "Subnet mask must be number!")
                continue
            dest_mask_int = int(dest_mask)
            if dest_mask_int < 0 or dest_mask_int > 32:
                message_box(screen, "Invalid subnet mask range!")
                continue
            break
        destination_cidr = f"{dest_ip}/{dest_mask_int}"
        # Gateway
        while True:
            gateway = input_box(screen, "Enter Gateway IP of route to remove:")
            if gateway is None:
                return
            if not validate_ip(gateway):
                message_box(screen, "Invalid Gateway IP!")
                continue
            break
        try:
            remove_route_temporary(interface, destination_cidr, gateway)
            message_box(screen, "Route removed successfully!")
            logging.info(f"Route {destination_cidr} via {gateway} removed from {interface}")
            return
        except ValueError as ve:
            message_box(screen, f"{ve}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error removing route: {e}")
            message_box(screen, f"Error: {e}")

def network_configuration_menu(screen):
    """
    Network Configuration Menu (Phase 1).
    """
    selected = 0
    options = ["Change DNS",
               "Change Hostname",
               "Set Static IP",
               "Use DHCP",
               "Add Route",
               "Remove Route",
               "Back to Main Menu"]
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(screen, 2, 2, "Network Configuration Menu (ESC to go back)", screen.getmaxyx()[1]-4)
        for idx, option in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + option, screen.getmaxyx()[1]-4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [curses.KEY_ENTER, 10,13]:
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


########################################
# Phase 2: Nftables Management          #
########################################

def check_nft_installed(screen):
    """
    Check if nft is installed and nftables service is running.
    If not installed, try to install and enable.
    Use 'nftables.service' explicitly.
    If service fails to start, log warning but continue if nft works.
    """
    # Check nft command availability
    try:
        subprocess.check_output(["which", "nft"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        # nft not found, attempt installation
        message_box(screen, "nft command not found.\nAttempting to install nftables...")
        try:
            run_command(["apt-get", "update"])
            run_command(["apt-get", "install", "-y", "nftables"])
        except Exception as e:
            message_box(screen, f"Failed to install nftables:\n{e}")
            return False

    # Check nft version to confirm it works
    try:
        subprocess.check_output(["nft", "--version"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        message_box(screen, f"Error running 'nft --version':\n{e}")
        return False

    # Try enabling and starting nftables.service
    # Some systems may already have it active or may not require the service.
    try:
        status = subprocess.check_output(["systemctl", "is-active", "nftables.service"], universal_newlines=True).strip()
        if status != "active":
            # Try to enable and start
            try:
                run_command(["systemctl", "enable", "nftables.service"])
                run_command(["systemctl", "start", "nftables.service"])
            except Exception as e:
                # If we fail to start the service, log a warning but continue
                # since rules can still be applied via nft directly.
                logging.warning(f"Failed to enable/start nftables.service:\n{e}")
                message_box(screen, f"Warning: Failed to enable/start nftables.service.\nContinuing anyway since nft is installed.")
    except subprocess.CalledProcessError:
        # systemctl is-active failed, try enabling and starting anyway
        try:
            run_command(["systemctl", "enable", "nftables.service"])
            run_command(["systemctl", "start", "nftables.service"])
        except Exception as e:
            # If service can't be started, just warn and continue.
            logging.warning(f"Failed to enable/start nftables.service:\n{e}")
            message_box(screen, f"Warning: Failed to enable/start nftables.service.\nContinuing anyway.")

    # Ensure /etc/nftables.conf structure
    ensure_nftables_conf(screen)

    return True

def ensure_nftables_conf(screen):
    """
    Ensure /etc/nftables.conf has basic inet filter and ip nat tables.
    This provides a foundation for adding rules without syntax errors.
    """
    conf_path = "/etc/nftables.conf"
    # Include both filter and nat tables by default
    if not os.path.exists(conf_path) or os.path.getsize(conf_path) == 0:
        default_conf = """#!/usr/sbin/nft -f
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
            message_box(screen, f"Error creating /etc/nftables.conf:\n{e}")

def validate_action(screen, action, allowed_actions):
    """Ensure the chosen action is one of the allowed_actions."""
    while action not in allowed_actions:
        message_box(screen, f"Invalid action: {action}\nAllowed: {', '.join(allowed_actions)}")
        action = input_box(screen, f"Re-enter action ({'/'.join(allowed_actions)}):")
        if action is None:
            return None
    return action

def validate_ip_input(screen, prompt):
    """Prompt user for IP and validate it."""
    while True:
        val = input_box(screen, prompt)
        if val is None:
            return None
        if not validate_ip(val):
            message_box(screen, f"Invalid IP Address: {val}")
            continue
        return val

def apply_nft_rule(screen, rule, nat=False):
    """
    Append the rule to /etc/nftables.conf and apply with `nft -f`.
    If nat=False (filter rule): Add to 'inet filter input'.
    If nat=True (NAT rule): Determine chain by rule type:
       - masquerade -> postrouting (ip nat)
       - dnat -> prerouting (ip nat)
    """
    conf_path = "/etc/nftables.conf"

    if nat:
        if "masquerade" in rule:
            # NAT postrouting
            full_rule = f"add rule ip nat postrouting {rule}\n"
        elif "dnat to" in rule:
            # DNAT prerouting
            full_rule = f"add rule ip nat prerouting {rule}\n"
        else:
            message_box(screen, "Error: Unknown NAT rule pattern.")
            return
    else:
        # Filter rule
        full_rule = f"add rule inet filter input {rule}\n"

    try:
        with open(conf_path, 'a') as f:
            f.write(full_rule)

        run_command(["nft", "-f", conf_path])
        message_box(screen, "Rule added successfully!")
        logging.info(f"Added nftables rule: {full_rule.strip()}")
    except Exception as e:
        logging.error(f"Error applying nft rule: {e}")
        message_box(screen, f"Error applying rule:\n{e}")

#####################
# Phase 2 Rule Forms#
#####################

def ct_state_rule_form(screen):
    """ct_state rule: in filter table input chain."""
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
    action = validate_action(screen, action, allowed_actions)
    if action is None:
        return

    rule = f"ct state {state} {action}"
    apply_nft_rule(screen, rule, nat=False)

def ip_proto_rule_form(screen):
    """IP-based rule (tcp/udp) in filter table input chain."""
    src = validate_ip_input(screen, "Enter source IP (e.g. 0.0.0.0/0):")
    if src is None:
        return
    dst = validate_ip_input(screen, "Enter destination IP:")
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

    dport = input_box(screen, "Enter destination port (e.g. 80):")
    if dport is None:
        return
    if not dport.isdigit() or not (1 <= int(dport) <= 65535):
        message_box(screen, f"Invalid port: {dport}")
        return

    allowed_actions = ["accept", "drop", "reject"]
    action = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if action is None:
        return
    action = validate_action(screen, action, allowed_actions)
    if action is None:
        return

    rule = f"ip saddr {src} ip daddr {dst} {proto} dport {dport} {action}"
    apply_nft_rule(screen, rule, nat=False)

def icmp_rule_form(screen):
    """ICMP rule in filter table input chain."""
    src = validate_ip_input(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input(screen, "Enter destination IP:")
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
    action = input_box(screen, f"Enter action ({'/'.join(allowed_actions)}):")
    if action is None:
        return
    action = validate_action(screen, action, allowed_actions)
    if action is None:
        return

    # For icmp, we can just say `icmp type echo-request accept`
    # No 'ip protocol icmp' needed.
    rule = f"ip saddr {src} ip daddr {dst} icmp type {icmp_type} {action}"
    apply_nft_rule(screen, rule, nat=False)

def masquerade_rule_form(screen):
    """Masquerade rule (NAT postrouting)."""
    src = validate_ip_input(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input(screen, "Enter destination IP:")
    if dst is None:
        return

    # Masquerade applies to NAT postrouting chain
    rule = f"ip saddr {src} ip daddr {dst} masquerade"
    apply_nft_rule(screen, rule, nat=True)

def dnat_rule_form(screen):
    """DNAT rule (NAT prerouting)."""
    src = validate_ip_input(screen, "Enter source IP:")
    if src is None:
        return
    dst = validate_ip_input(screen, "Enter destination IP:")
    if dst is None:
        return
    dport = input_box(screen, "Enter destination port:")
    if dport is None:
        return
    if not dport.isdigit() or not (1 <= int(dport) <= 65535):
        message_box(screen, f"Invalid port: {dport}")
        return
    new_target = input_box(screen, "Enter DNAT target (IP:PORT):")
    if new_target is None:
        return
    if ':' not in new_target:
        message_box(screen, "Invalid DNAT target format, use IP:PORT")
        return
    ip_part, port_part = new_target.split(':', 1)
    if not validate_ip(ip_part):
        message_box(screen, f"Invalid IP in DNAT target: {ip_part}")
        return
    if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
        message_box(screen, f"Invalid port in DNAT target: {port_part}")
        return

    rule = f"ip saddr {src} ip daddr {dst} tcp dport {dport} dnat to {new_target}"
    apply_nft_rule(screen, rule, nat=True)

############################
# Phase 2 Nftables Menu    #
############################

def nftables_menu(screen):
    """
    Nftables menu for phase 2.
    """
    if not check_nft_installed(screen):
        return

    selected = 0
    options = ["Create ct_state rule",
               "Create IP-based rule",
               "Create ICMP rule",
               "Create masquerade rule",
               "Create DNAT rule",
               "Back to Main Menu"]

    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(screen, 2, 2, "Nftables Menu (Phase 2) (ESC to go back)", screen.getmaxyx()[1]-4)
        for idx, option in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + option, screen.getmaxyx()[1]-4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [curses.KEY_ENTER, 10,13]:
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

############################
# Main Menu (Phase 1 & 2)  #
############################

def main_menu(screen):
    """
    Main Menu including Phase 1 and Phase 2 options.
    """
    selected = 0
    options = ["Network Configuration",
               "Manage Firewall (Nftables)",
               "Open vSwitch Management",
               "Network Monitoring",
               "Exit"]
    while True:
        screen.clear()
        screen.border(0)
        print_wrapped(screen, 2, 2, "Main Menu (ESC to exit)", screen.getmaxyx()[1]-4)
        for idx, option in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4+idx, 2, prefix + option, screen.getmaxyx()[1]-4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [curses.KEY_ENTER, 10, 13]:
            if selected == 0:
                network_configuration_menu(screen)
            elif selected == 1:
                nftables_menu(screen)
            elif selected == 2:
                message_box(screen, "Open vSwitch Management - Not Implemented")
            elif selected == 3:
                message_box(screen, "Network Monitoring - Not Implemented")
            elif selected == 4:
                break
        elif key == 27:
            break

def main(screen):
    """Entry point: Check root, set logging, run main menu."""
    if os.geteuid() != 0:
        screen.clear()
        screen.border(0)
        message_box(screen, "Error: Must run as root.\nPress any key to exit.")
        return

    logging.basicConfig(
        filename='network_configuration.log',
        level=logging.INFO,
        format='%(asctime)s %(levelname)s:%(message)s'
    )

    main_menu(screen)

if __name__ == '__main__':
    curses.wrapper(main)