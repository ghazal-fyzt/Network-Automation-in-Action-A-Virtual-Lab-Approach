#!/usr/bin/env python3

import curses
import logging
import ipaddress
import os
import subprocess

# Configure logging
logging.basicConfig(filename='network_configuration.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

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
    """
    Input box that allows ESC or 'back' to go back (returns None).
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
    print_wrapped(screen, y+1, 2, "(Press ESC to go back, or type 'back' to return)", max_x - 4)

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
        elif ch == curses.KEY_BACKSPACE or ch == 127:
            if buffer:
                buffer.pop()
                screen.delch(input_y, input_x + len(buffer))
        elif ch == 10:  # Enter
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

def select_interface(screen):
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
        elif key == curses.KEY_ENTER or key in [10, 13]:
            return interfaces[selected]
        elif key == 27:
            return None

def select_permanence(screen):
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
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if options[selected] == "Back":
                return None
            return (selected == 1)  # True if permanently selected
        elif key == 27:
            return None

def get_network_interfaces():
    return os.listdir('/sys/class/net/')

def run_command(cmd):
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)

def validate_ip(ip_str):
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except:
        return False

def route_exists(destination_cidr, gateway, interface_name):
    output = subprocess.check_output(['ip', 'route', 'show'], universal_newlines=True)
    route_line = f"{destination_cidr} via {gateway} dev {interface_name}"
    return route_line in output

def add_route_temporary(interface_name, destination_cidr, gateway):
    cmd = ['ip', 'route', 'add', destination_cidr, 'via', gateway, 'dev', interface_name]
    subprocess.check_call(cmd)

    # Check if route exists after addition
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after addition. Something went wrong.")

def add_route_permanent(interface_name, destination_cidr, gateway):
    # Use nmcli to add permanent route
    try:
        run_command(['nmcli', 'connection', 'modify', interface_name, '+ipv4.routes', f"{destination_cidr} {gateway}"])
        run_command(['nmcli', 'connection', 'up', interface_name])
    except subprocess.CalledProcessError as e:
        # If fails, raise exception
        raise e

    # Check if route exists after addition
    if not route_exists(destination_cidr, gateway, interface_name):
        raise ValueError("Route not found after permanent addition. Something went wrong.")

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
    # Always permanent for DHCP
    run_command(['nmcli', 'connection', 'modify', interface_name, 'ipv4.method', 'auto'])
    run_command(['nmcli', 'connection', 'up', interface_name])

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
                message_box(screen, "DNS Servers cannot be empty! Press any key to retry.")
                continue
            dns_list = [dns.strip() for dns in dns_servers.split(',') if dns.strip()]
            if len(dns_list) == 0:
                message_box(screen, "No valid DNS servers entered! Please try again.")
                continue
            if len(dns_list) > 3:
                message_box(screen, "You entered more than 3 DNS servers. Please enter up to 3.")
                continue
            valid_dns = True
            for dns in dns_list:
                if not validate_ip(dns):
                    message_box(screen, f"Invalid DNS Server IP: {dns}\nPlease enter a valid IPv4 address.")
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
                logging.info(f"DNS Servers updated to {dns_list} on interface {interface}, permanent={permanent}")
                return
            except Exception as e:
                logging.error(f"Error updating DNS Servers: {e}")
                message_box(screen, f"Error updating DNS Servers:\n{e}\nPress any key to retry.")
        return

def change_hostname_form(screen):
    while True:
        hostname = input_box(screen, "Enter New Hostname:")
        if hostname is None:
            return
        if not hostname:
            message_box(screen, "Hostname cannot be empty! Press any key to retry.")
            continue
        try:
            change_hostname(hostname)
            message_box(screen, "Hostname changed successfully!")
            logging.info(f"Hostname changed to {hostname}")
            return
        except Exception as e:
            logging.error(f"Error changing hostname: {e}")
            message_box(screen, f"Error changing hostname:\n{e}\nPress any key to retry.")

def set_static_ip_form(screen):
    while True:
        interface = select_interface(screen)
        if interface is None:
            return

        # IP Address
        while True:
            ip_address = input_box(screen, "Enter IP Address (e.g. 192.168.1.10):")
            if ip_address is None:
                return
            if not validate_ip(ip_address):
                message_box(screen, "Invalid IP Address.\nPlease enter a valid IPv4 address.\nPress any key to try again.")
                continue
            break

        # Subnet Mask
        while True:
            subnet_mask = input_box(screen, "Enter Subnet Mask in CIDR (0-32), e.g. 24:")
            if subnet_mask is None:
                return
            if not subnet_mask.isdigit():
                message_box(screen, "Subnet mask must be a number between 0 and 32.\nPress any key to try again.")
                continue
            mask_int = int(subnet_mask)
            if mask_int < 0 or mask_int > 32:
                message_box(screen, "Invalid subnet mask! Must be between 0 and 32.\nPress any key to try again.")
                continue
            break

        # Gateway (optional)
        while True:
            gw_input = input_box(screen, "Enter Gateway IP (Optional, leave blank if none):")
            if gw_input is None:
                return
            if gw_input == '':
                gateway = ''
                break
            if not validate_ip(gw_input):
                message_box(screen, "Invalid Gateway IP.\nPlease enter a valid IPv4 address.\nPress any key to try again.")
                continue
            try:
                network = ipaddress.ip_network(f"{ip_address}/{mask_int}", strict=False)
                if ipaddress.IPv4Address(gw_input) not in network:
                    message_box(screen, f"Gateway {gw_input} is not in the same network as {ip_address}/{mask_int}.\n"
                                        "Ensure the gateway is in the same subnet.\nPress any key to try again.")
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
            logging.info(f"Static IP {ip_address}/{mask_int} set on interface {interface}, permanent={permanent}")
            return
        except Exception as e:
            logging.error(f"Error setting static IP: {e}")
            message_box(screen, f"Error setting static IP:\n{e}\nPress any key to retry.")

def use_dhcp_form(screen):
    while True:
        interface = select_interface(screen)
        if interface is None:
            return
        try:
            use_dhcp(interface)
            message_box(screen, "DHCP enabled successfully (permanent)!")
            logging.info(f"DHCP enabled on interface {interface} permanently.")
            return
        except Exception as e:
            logging.error(f"Error enabling DHCP: {e}")
            message_box(screen, f"Error enabling DHCP:\n{e}\nPress any key to retry.")

def add_route_form(screen):
    while True:
        interface = select_interface(screen)
        if interface is None:
            return

        # Destination IP
        while True:
            dest_ip = input_box(screen, "Enter Destination Network IP (e.g., 192.168.1.0):")
            if dest_ip is None:
                return
            if not validate_ip(dest_ip):
                message_box(screen, "Invalid Destination IP.\nPlease enter a valid IPv4 address.\nPress any key to try again.")
                continue
            break

        # Subnet Mask
        while True:
            dest_mask = input_box(screen, "Enter Destination Network Mask in CIDR (0-32), e.g. 24:")
            if dest_mask is None:
                return
            if not dest_mask.isdigit():
                message_box(screen, "Subnet mask must be a number between 0 and 32.\nPress any key to try again.")
                continue
            dest_mask_int = int(dest_mask)
            if dest_mask_int < 0 or dest_mask_int > 32:
                message_box(screen, "Invalid subnet mask! Must be between 0 and 32.\nPress any key to try again.")
                continue
            break

        destination_cidr = f"{dest_ip}/{dest_mask_int}"

        # Gateway
        while True:
            gateway = input_box(screen, "Enter Gateway IP:")
            if gateway is None:
                return
            if not gateway or not validate_ip(gateway):
                message_box(screen, "Invalid Gateway IP.\nPlease enter a valid IPv4 address.\nPress any key to try again.")
                continue
            break

        # Select permanence
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
            logging.info(f"Route to {destination_cidr} via {gateway} on interface {interface}, permanent={permanent}")
            return
        except ValueError as ve:
            message_box(screen, f"{ve}\nPress any key to retry.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error adding route: {e}")
            message_box(screen, f"Error adding route:\n{e}\nPress any key to retry.")

def remove_route_form(screen):
    while True:
        interface = select_interface(screen)
        if interface is None:
            return

        while True:
            dest_ip = input_box(screen, "Enter Destination Network IP of route to remove (e.g., 192.168.1.0):")
            if dest_ip is None:
                return
            if not validate_ip(dest_ip):
                message_box(screen, "Invalid Destination IP.\nPlease enter a valid IPv4 address.\nPress any key to try again.")
                continue
            break

        while True:
            dest_mask = input_box(screen, "Enter Destination Network Mask in CIDR (0-32) of route to remove, e.g. 24:")
            if dest_mask is None:
                return
            if not dest_mask.isdigit():
                message_box(screen, "Subnet mask must be a number between 0 and 32.\nPress any key to try again.")
                continue
            dest_mask_int = int(dest_mask)
            if dest_mask_int < 0 or dest_mask_int > 32:
                message_box(screen, "Invalid subnet mask! Must be between 0 and 32.\nPress any key to try again.")
                continue
            break

        destination_cidr = f"{dest_ip}/{dest_mask_int}"

        while True:
            gateway = input_box(screen, "Enter Gateway IP of route to remove:")
            if gateway is None:
                return
            if not gateway or not validate_ip(gateway):
                message_box(screen, "Invalid Gateway IP.\nPlease enter a valid IPv4 address.\nPress any key to try again.")
                continue
            break

        try:
            remove_route_temporary(interface, destination_cidr, gateway)
            message_box(screen, "Route removed successfully!")
            logging.info(f"Route {destination_cidr} via {gateway} removed from {interface}")
            return
        except ValueError as ve:
            message_box(screen, f"{ve}\nPress any key to retry.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Error removing route: {e}")
            message_box(screen, f"Error removing route:\n{e}\nPress any key to retry.")

def network_configuration_menu(screen):
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
        elif key == curses.KEY_ENTER or key in [10, 13]:
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

def main_menu(screen):
    selected = 0
    options = ["Network Configuration",
               "Manage Firewall",
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
        elif key == curses.KEY_ENTER or key in [10, 13]:
            if selected == 0:
                network_configuration_menu(screen)
            elif selected == 1:
                message_box(screen, "Manage Firewall - Not Implemented")
            elif selected == 2:
                message_box(screen, "Open vSwitch Management - Not Implemented")
            elif selected == 3:
                message_box(screen, "Network Monitoring - Not Implemented")
            elif selected == 4:
                break
        elif key == 27:
            break

def main(screen):
    if os.geteuid() != 0:
        message_box(screen, "Error: This script must be run with sudo/root privileges.\nPress any key to exit.")
        return
    main_menu(screen)

if __name__ == '__main__':
    curses.wrapper(main)
