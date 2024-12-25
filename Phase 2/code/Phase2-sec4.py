import curses
import ipaddress
import os
import subprocess
import logging
import time

# ------------------ Phase 4 Logger ------------------ #
phase4_logger = logging.getLogger("phase4_logger")
phase4_logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
file_handler = logging.FileHandler('phase4.log')
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
        text = text[:max_width-1]
    screen.addstr(start_y, start_x, text)

def message_box(screen, message):
    """
    Display a message in a box. The user presses a key to continue.
    Useful for confirmations, errors, or notifications.
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
    Prompt user for input with a single line. 
    Press ESC or type 'back' to return None (go back).
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
                screen.addch(input_y, input_x + len(buffer)-1, ch)

def run_command(cmd):
    """
    Run a shell command quietly, raise on failure.
    """
    with open(os.devnull, 'w') as devnull:
        subprocess.check_call(cmd, stdout=devnull, stderr=devnull)

##############################
# Phase 4: Network Monitoring
##############################

def get_interfaces():
    """
    Return a list of network interfaces on the system by reading /sys/class/net.
    """
    return os.listdir('/sys/class/net')

def interface_is_up(iface):
    """
    Return True if 'iface' is UP, False otherwise, by checking 'cat /sys/class/net/iface/operstate'.
    """
    try:
        with open(f"/sys/class/net/{iface}/operstate", "r") as f:
            state = f.read().strip()
            return (state == "up")
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
        output = subprocess.check_output(["ip", "-4", "addr", "show", iface],
                                         universal_newlines=True)
        for line in output.splitlines():
            line=line.strip()
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
    stats = {"tcp_established": 0, "tcp_listen": 0,
             "udp_in_datagrams": 0, "udp_out_datagrams": 0}
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
        tcp_est_out = subprocess.check_output(["ss", "-t", "-a", "-n", "state", "established"],
                                              universal_newlines=True)
        # first line is a header, subsequent lines are connections
        lines = tcp_est_out.strip().split("\n")
        if len(lines) > 1:
            stats["tcp_established"] = len(lines) - 1
    except subprocess.CalledProcessError:
        pass
    # count tcp listening
    try:
        tcp_listen_out = subprocess.check_output(["ss", "-t", "-a", "-n", "state", "listening"],
                                                 universal_newlines=True)
        lines = tcp_listen_out.strip().split("\n")
        if len(lines) > 1:
            stats["tcp_listen"] = len(lines) - 1
    except subprocess.CalledProcessError:
        pass
    # for UDP, let's just do 'ss -u -a'
    try:
        udp_out = subprocess.check_output(["ss", "-u", "-a", "-n"],
                                          universal_newlines=True)
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
    print_wrapped(screen, 1, 2, "Interfaces Information (Press any key to return)", max_x - 4)
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
    print_wrapped(screen, y, 2, f"TCP Established: {stats['tcp_established']}", max_x - 4)
    y += 1
    print_wrapped(screen, y, 2, f"TCP Listening:   {stats['tcp_listen']}", max_x - 4)
    y += 2
    # 'udp_in_datagrams' is just how many open sockets we found from 'ss -u'
    print_wrapped(screen, y, 2, f"UDP Sockets Found: {stats['udp_in_datagrams']}", max_x - 4)
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
    print_wrapped(screen, 1, 2, "Interface Traffic Statistics (Press any key to return)", max_x - 4)
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
            if c == ord('q') or c == ord('Q'):
                break

            screen.clear()
            screen.border(0)
            print_wrapped(screen, 1, 2, "Real-time Bandwidth (press 'q' to quit)", max_x - 4)
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
    selected = 0
    options = [
        "View Network Interfaces Information",
        "View Network Bandwidth in Real-time",
        "View Network Protocol Statistics (TCP/UDP)",
        "View Bytes/Packets for Interfaces",
        "Exit Phase 4"
    ]
    while True:
        screen.clear()
        screen.border(0)
        max_y, max_x = screen.getmaxyx()
        print_wrapped(screen, 2, 2, "Phase 4: Network Monitoring (ESC to exit)", max_x - 4)
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

def main(stdscr):
    if os.geteuid() != 0:
        stdscr.clear()
        stdscr.border(0)
        message_box(stdscr, "Error: Must run as root.\nPress any key to exit.")
        return
    network_monitoring_menu(stdscr)

if __name__ == '__main__':
    curses.wrapper(main)