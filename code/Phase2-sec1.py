import curses
import ipaddress
import os
import subprocess
import logging

# ------------------ Phase 1 Logger ------------------ #
phase1_logger = logging.getLogger("phase1_logger")
phase1_logger.setLevel(logging.INFO)
p1_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
p1_handler = logging.FileHandler('phase1.log')
p1_handler.setLevel(logging.INFO)
p1_handler.setFormatter(p1_formatter)
phase1_logger.addHandler(p1_handler)

##############################
# Common Curses Helpers
##############################
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

    print_wrapped(screen, y+1, 2, "(Press ESC or type 'back' to return)", max_x - 4)
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
            if user_input.lower() == "back":
                return None
            return user_input
        elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT, curses.KEY_UP, curses.KEY_DOWN):
            continue
        else:
            if 32 <= ch <= 126:
                buffer.append(chr(ch))
                screen.addch(input_y, input_x + len(buffer)-1, ch)

##############################
# Phase 1 Functions
##############################
def run_command(cmd):
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)

def validate_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except:
        return False

def get_network_interfaces():
    return os.listdir('/sys/class/net/')

def route_exists(destination_cidr, gateway, interface_name):
    output = subprocess.check_output(['ip', 'route', 'show'], universal_newlines=True)
    route_line = f"{destination_cidr} via {gateway} dev {interface_name}"
    return route_line in output

def add_route_temporary(interface_name, destination_cidr, gateway):
    cmd = ['ip', 'route', 'add', destination_cidr, 'via', gateway, 'dev', interface_name]
    subprocess.check_call(cmd)
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after addition.")

def add_route_permanent(interface_name, destination_cidr, gateway):
    run_command(['nmcli', 'connection', 'modify', interface_name, '+ipv4.routes', f"{destination_cidr} {gateway}"])
    run_command(['nmcli', 'connection', 'up', interface_name])
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after permanent addition.")

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

#################
# Phase 1 TUI   #
#################

def select_interface(screen):
    interfaces = get_network_interfaces()
    selected = 0
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Select Interface (ESC to go back)", max_x - 4)
        for idx, iface in enumerate(interfaces):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + iface, max_x - 4)
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
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Apply Change:", max_x - 4)
        for idx, option in enumerate(options):
            prefix = "> " if idx == selected else "  "
            print_wrapped(screen, 4 + idx, 2, prefix + option, max_x - 4)
        key = screen.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in [10, 13]:
            if options[selected] == "Back":
                return None
            return (selected == 1)
        elif key == 27:
            return None

def change_dns_form(screen):
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
                message_box(screen, "More than 3 DNS servers entered!")
                continue
            valid = True
            for d in dns_list:
                if not validate_ip(d):
                    message_box(screen, f"Invalid DNS IP: {d}")
                    valid = False
                    break
            if not valid:
                continue

            p = select_permanence(screen)
            if p is None:
                break
            permanent = p

            try:
                change_dns(interface, dns_list, permanent)
                message_box(screen, "DNS updated successfully!")
                phase1_logger.info(f"DNS updated to {dns_list} on {interface}, permanent={permanent}")
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
        iface = select_interface(screen)
        if iface is None:
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
                message_box(screen, "Subnet mask must be numeric!")
                continue
            mask_int = int(subnet_mask)
            if mask_int < 0 or mask_int > 32:
                message_box(screen, "Subnet mask out of range (0-32)!")
                continue
            break
        gateway = ''
        while True:
            gw = input_box(screen, "Enter Gateway IP (Optional):")
            if gw is None:
                return
            if gw == '':
                gateway = ''
                break
            if not validate_ip(gw):
                message_box(screen, "Invalid Gateway IP!")
                continue
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
            set_static_ip(iface, ip_address, mask_int, gateway, permanent)
            message_box(screen, "Static IP set successfully!")
            phase1_logger.info(f"Set static IP {ip_address}/{mask_int} on {iface}, permanent={permanent}")
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
                message_box(screen, "Invalid mask range!")
                continue
            break
        cidr = f"{dest_ip}/{dm}"
        while True:
            gw = input_box(screen, "Enter Gateway IP:")
            if gw is None:
                return
            if not validate_ip(gw):
                message_box(screen, "Invalid Gateway IP!")
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
            phase1_logger.info(f"Route {cidr} via {gw} on {iface}, perm={permanent}")
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
                message_box(screen, "Invalid Gateway IP!")
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
    selected = 0
    options = [
        "Change DNS",
        "Change Hostname",
        "Set Static IP",
        "Use DHCP",
        "Add Route",
        "Remove Route",
        "Exit Phase 1"
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Phase 1: Network Configuration (ESC to exit)", max_x - 4)
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

def main(stdscr):
    if os.geteuid() != 0:
        stdscr.clear()
        stdscr.border(0)
        message_box(stdscr, "Error: Must run as root.\nPress any key to exit.")
        return
    network_configuration_menu(stdscr)

if __name__ == '__main__':
    curses.wrapper(main)
