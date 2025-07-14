import paramiko
import time
from prettytable import PrettyTable

# SSH credentials and host information
hosts = [
    {"hostname": "XXX.XXX.XXX.XXX", "port": 22, "username": "<username>", "password": "<password>"},
]

# # Command to fetch GPU information using nvidia-smi
# command = "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu --format=csv,nounits"


# def fetch_gpu_info(host):
#     """Fetch GPU information from a given host."""
#     try:
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(host['hostname'], port=host['port'], username=host['username'], password=host['password'])
#         stdin, stdout, stderr = ssh.exec_command(command)
#         output = stdout.read().decode('utf-8')
#         ssh.close()
#         return output.strip().split('\n')[1:]  # Skip the header line
#     except Exception as e:
#         print(f"Error fetching GPU info from {host['hostname']}: {e}")
#         return []


# def print_dynamic_table():
#     """Fetch GPU info from all hosts and print the dynamic table."""
#     table = PrettyTable()
#     table.field_names = ["Host", "GPU Index", "GPU Name", "Memory Total (MiB)", "Memory Used (MiB)", "Utilization (%)"]

#     for host in hosts:
#         gpu_info = fetch_gpu_info(host)
#         for line in gpu_info:
#             data = line.split(',')
#             table.add_row([host['hostname']] + [elem.strip() for elem in data])
#         # Add a separator line after each host's info
#         table.add_row(['-' * 6] * len(table.field_names))

#     print("\033c", end="")  # Clear the screen
#     print(table)


# def shot_main():
#     while True:
#         print_dynamic_table()
#         time.sleep(1)  # Refresh every 60 seconds


# if __name__ == "__main__":
#     shot_main()

command = "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu --format=csv,noheader,nounits"

# Refresh interval in seconds
REFRESH_INTERVAL = 10
CONNECT_TIMEOUT = 60 # Connection timeout in seconds
COMMAND_TIMEOUT = 60 # Command execution timeout in seconds

# Dictionary to store active SSHClient objects {(hostname, port): client}
ssh_connections = {}

# --- Helper Function ---
def get_host_key(host):
    """Creates a unique key tuple (hostname, port) for the connections dictionary."""
    # Use default SSH port 22 if not specified in the host dictionary
    return (host['hostname'], host.get('port', 22))

# --- Core Functions ---

def connect_to_host(host):
    """Attempts to establish an SSH connection to a single host config."""
    hostname = host['hostname']
    port = host.get('port', 22)
    host_key = (hostname, port) # For logging clarity

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"Connecting to {hostname}:{port}...")
        # Use password if provided, otherwise assumes key-based auth
        connect_args = {
            'hostname': hostname,
            'port': port,
            'username': host['username'],
            'timeout': CONNECT_TIMEOUT
        }
        if 'password' in host:
            connect_args['password'] = host['password']
            # Optimization: Don't look for keys if password is given
            connect_args['look_for_keys'] = False
            connect_args['allow_agent'] = False

        ssh.connect(**connect_args)
        print(f"Successfully connected to {hostname}:{port}.")
        return ssh
    except paramiko.AuthenticationException:
        print(f"Authentication failed for {hostname}:{port}.")
        return None
    except Exception as e:
        print(f"Failed to connect to {hostname}:{port}: {e}")
        return None

def initialize_connections():
    """Establishes initial connections based on the hosts list."""
    print("Initializing SSH connections...")
    for host in hosts:
        host_key = get_host_key(host) # Use (hostname, port) tuple as key
        if host_key not in ssh_connections: # Avoid reconnecting if already somehow connected
            ssh_client = connect_to_host(host)
            if ssh_client:
                ssh_connections[host_key] = ssh_client # Store using the tuple key
            else:
                # Decide if failure to connect initially is critical
                # print(f"Warning: Could not establish initial connection to {host['hostname']}:{host.get('port', 22)}.")
                pass # Continue trying to connect to others

def close_all_connections():
    """Closes all active SSH connections stored in the dictionary."""
    print("\nClosing SSH connections...")
    # Iterate through a copy of keys in case of issues during close
    for host_key, client in list(ssh_connections.items()):
        hostname, port = host_key
        try:
            if client and client.get_transport() and client.get_transport().is_active():
                print(f"Closing connection to {hostname}:{port}...")
                client.close()
        except Exception as e:
            print(f"Error closing connection to {hostname}:{port}: {e}")
    ssh_connections.clear() # Clear the dictionary after attempting closures

def fetch_gpu_info_long(hostname, port, ssh_client):
    """Fetches GPU info using an existing SSH connection."""
    host_id_str = f"{hostname}:{port}" # For logging
    try:
        # Check if connection seems active before executing command
        transport = ssh_client.get_transport()
        if not (transport and transport.is_active()):
            print(f"Connection to {host_id_str} appears inactive.")
            return None # Signal connection issue

        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=COMMAND_TIMEOUT)
        output = stdout.read().decode('utf-8').strip()
        error_output = stderr.read().decode('utf-8').strip()

        # It's good practice to check the exit status
        exit_status = stdout.channel.recv_exit_status()

        if exit_status != 0:
            # Log stderr if command failed
            error_msg = error_output if error_output else "No stderr output"
            print(f"Command exited with status {exit_status} on {host_id_str}. Error: {error_msg}")
            # Treat non-zero exit status as a failure, return empty list
            return []

        # If exit status is 0, but there was stderr output, it might be warnings
        if error_output:
             print(f"Command on {host_id_str} produced stderr (exit status 0): {error_output}")
             # Continue processing stdout even if there are warnings

        # Return lines from stdout, or empty list if no output
        return output.split('\n') if output else []

    except paramiko.SSHException as e:
        print(f"SSHException on {host_id_str} (connection likely lost): {e}")
        return None # Signal connection issue
    except Exception as e: # Catches timeouts from exec_command etc.
        print(f"Error during command execution on {host_id_str}: {e}")
        return None # Signal potential connection issue or command error

# --- 辅助函数 ---
def get_host_key(host_config): # 参数名修改以增加清晰度
    """为连接字典创建一个唯一的键元组 (hostname, port)。"""
    return (host_config['hostname'], host_config.get('port', 22))

# --- 你现有的 connect_to_host, initialize_connections, close_all_connections, fetch_gpu_info_long 函数 ---
# (确保它们在 print_dynamic_table 之前定义，或者根据需要作为参数传递)

def print_dynamic_table():
    """
    获取GPU信息并打印动态表格，表格行顺序严格按照全局 'hosts' 列表的顺序。
    """
    global hosts # 确保我们使用全局的 hosts 列表来决定顺序
    global ssh_connections # 用于访问和管理SSH连接

    table = PrettyTable()
    table.field_names = ["主机", "GPU索引", "GPU名称", "总显存 (MiB)", "已用显存 (MiB)", "利用率 (%)"]
    hosts_keys_to_remove_from_dict = [] # 跟踪那些连接失败的键，以便从 ssh_connections 字典中清理

    if not hosts:
        print("没有配置任何主机。")
        return

    # 1. 核心改动：遍历全局的 `hosts` 列表来保证打印顺序
    for host_config in hosts:
        host_key = get_host_key(host_config)
        hostname, port = host_key # 解包主机键
        display_host = f"{hostname}:{port}" # 用于表格中显示的主机名
        # 动态生成分隔符，使其与主机名长度对齐
        separator = ['-' * len(display_host)] + ['-' * 18] * (len(table.field_names) - 1)

        # 2. 从 ssh_connections 字典中获取该主机的SSH客户端对象
        ssh_client = ssh_connections.get(host_key)

        # 3. 处理连接不存在或不活动的情况
        if not ssh_client or not (ssh_client.get_transport() and ssh_client.get_transport().is_active()):
            # 如果连接不存在、为None，或连接的transport不活动
            # main 函数中的重连逻辑会尝试重新连接这个主机。
            # 我们仍然按照 `hosts` 列表的顺序为这个主机添加一行，显示其当前状态。
            status_message = '连接中...'
            if host_key in ssh_connections: # 如果之前连接过，但现在不在了或不活动
                if ssh_client and not (ssh_client.get_transport() and ssh_client.get_transport().is_active()):
                    status_message = '连接丢失'
                    # 如果它之前在连接池中但现在不活动了，标记以便后续从连接池中移除并关闭
                    hosts_keys_to_remove_from_dict.append(host_key)
                else: # 在连接池中找不到，说明正在尝试连接
                     status_message = '尝试连接...'


            table.add_row([display_host, 'N/A', status_message, 'N/A', 'N/A', 'N/A'])
            table.add_row(separator)
            continue # 继续处理 `hosts` 列表中的下一个主机

        # 如果代码执行到这里，说明 ssh_client 存在并且被认为是活动的
        # (fetch_gpu_info_long 内部会再次检查连接状态)
        gpu_lines = fetch_gpu_info_long(hostname, port, ssh_client)

        if gpu_lines is None:
            # fetch_gpu_info_long 检测到连接错误（例如，命令执行时连接断开）
            print(f"主机 {display_host} 在执行命令期间连接失败。标记以便移除。")
            hosts_keys_to_remove_from_dict.append(host_key)
            table.add_row([display_host, 'N/A', '连接错误', 'N/A', 'N/A', 'N/A'])
            table.add_row(separator)
        elif not gpu_lines:
            # 命令成功执行但没有返回数据 (或者命令以非零状态码“干净地”失败了)
            table.add_row([display_host, 'N/A', '无GPU数据/命令错误', 'N/A', 'N/A', 'N/A'])
            table.add_row(separator)
        else:
            # 处理有效的GPU信息行
            added_row_for_host = False
            for line in gpu_lines:
                if not line.strip(): continue # 跳过空行
                try:
                    data = line.split(',')
                    if len(data) == 5: # 确保数据格式符合预期
                        table.add_row([display_host] + [elem.strip() for elem in data])
                        added_row_for_host = True
                    else:
                        print(f"警告: 主机 {display_host} 返回的数据格式不符合预期: {line}")
                except Exception as parse_error:
                    print(f"解析主机 {display_host} 的行数据时出错: '{line}' - {parse_error}")

            if added_row_for_host:
                table.add_row(separator) # 如果为该主机添加了实际数据行，则添加分隔符
            elif not added_row_for_host: # 处理命令运行正常但未找到GPU的情况
                table.add_row([display_host, 'N/A', '未找到GPU?', 'N/A', 'N/A', 'N/A'])
                table.add_row(separator)


    # --- 在遍历完 `hosts` 列表后，清理那些标记为失败/不活动的连接 ---
    for host_key_to_remove in hosts_keys_to_remove_from_dict:
        if host_key_to_remove in ssh_connections: # 再次确认键存在
            hostname_to_remove, port_to_remove = host_key_to_remove
            try:
                print(f"正在关闭到 {hostname_to_remove}:{port_to_remove} 的失败/不活动连接。")
                ssh_connections[host_key_to_remove].close()
            except Exception as e:
                print(f"关闭到 {hostname_to_remove}:{port_to_remove} 的失败连接时出错: {e}")
            finally:
                # 确保从活动连接字典中移除，即使关闭失败
                del ssh_connections[host_key_to_remove]


    # --- 打印表格 ---
    try:
        # 尝试使用 ANSI 转义序列清屏 (适用于大多数Linux/macOS终端)
        print("\033c", end="")
    except:
        #  备用方案，用于不支持 ANSI 的终端 (例如某些 Windows cmd)
        os.system('cls' if os.name == 'nt' else 'clear')

    print(f"GPU 状态刷新 ({time.strftime('%Y-%m-%d %H:%M:%S')})")
    print(table)
    print(f"将在 {REFRESH_INTERVAL} 秒后刷新...")
    if hosts_keys_to_remove_from_dict: # 使用更新后的变量名
        failed_hosts_str = ", ".join([f"{h}:{p}" for h, p in hosts_keys_to_remove_from_dict])
        print(f"本周期内已关闭以下主机的连接: {failed_hosts_str}。")

# def print_dynamic_table():
#     """Fetch GPU info using existing connections and print the dynamic table."""
#     table = PrettyTable()
#     # Make "Host" column wider to accommodate "hostname:port"
#     table.field_names = ["Host", "GPU Index", "GPU Name", "Memory Total (MiB)", "Memory Used (MiB)", "Utilization (%)"]
#     hosts_keys_to_remove = [] # Track keys for connections that failed

#     # Iterate through a copy of keys for safety during potential modifications
#     active_host_keys = list(ssh_connections.keys())

#     if not active_host_keys:
#          print("No active SSH connections.")

#     for host_key in active_host_keys:
#         hostname, port = host_key # Unpack the key
#         ssh_client = ssh_connections[host_key]
#         display_host = f"{hostname}:{port}" # Create the display string

#         gpu_lines = fetch_gpu_info_long(hostname, port, ssh_client) # Pass hostname and port for logging

#         separator = ['-' * len(display_host)] + ['-' * 18] * (len(table.field_names) - 1) # Dynamic separator

#         if gpu_lines is None:
#             # Connection error detected
#             print(f"Connection to {display_host} failed. Marking for removal.")
#             hosts_keys_to_remove.append(host_key)
#             table.add_row([display_host, 'N/A', 'CONNECTION ERROR', 'N/A', 'N/A', 'N/A'])
#             table.add_row(separator)
#         elif not gpu_lines:
#             # Command executed but returned no data (or failed cleanly with non-zero exit)
#             table.add_row([display_host, 'N/A', 'No GPU data / Cmd Error', 'N/A', 'N/A', 'N/A'])
#             table.add_row(separator)
#         else:
#             # Process valid GPU lines
#             added_row_for_host = False
#             for line in gpu_lines:
#                 if not line.strip(): continue # Skip empty lines
#                 try:
#                     data = line.split(',')
#                     # Basic validation - check number of elements
#                     if len(data) == 5:
#                          table.add_row([display_host] + [elem.strip() for elem in data])
#                          added_row_for_host = True
#                     else:
#                          print(f"Warning: Unexpected data format from {display_host}: {line}")
#                 except Exception as parse_error:
#                     print(f"Error parsing line from {display_host}: '{line}' - {parse_error}")

#             # Add separator only if we added actual data rows for this host
#             if added_row_for_host:
#                 table.add_row(separator)
#             elif not added_row_for_host: # Handle case where command ran but found no GPUs
#                  table.add_row([display_host, 'N/A', 'No GPUs Found?', 'N/A', 'N/A', 'N/A'])
#                  table.add_row(separator)


#     # --- Clean up connections that failed AFTER iteration ---
#     for host_key in hosts_keys_to_remove:
#         if host_key in ssh_connections:
#             hostname, port = host_key
#             try:
#                 print(f"Closing failed connection to {hostname}:{port}.")
#                 ssh_connections[host_key].close()
#             except Exception as e:
#                 print(f"Error closing failed connection to {hostname}:{port}: {e}")
#             finally:
#                  # Ensure removal even if close fails
#                  del ssh_connections[host_key]


#     # --- Printing ---
#     try:
#         # Attempt standard ANSI clear screen
#         print("\033c", end="")
#     except:
#         # Fallback for terminals that don't support it (e.g., basic Windows cmd)
#         os.system('cls' if os.name == 'nt' else 'clear')

#     print(f"GPU Status Refresh ({time.strftime('%Y-%m-%d %H:%M:%S')})")
#     print(table)
#     print(f"Refreshing in {REFRESH_INTERVAL} seconds...")
#     if hosts_keys_to_remove:
#         failed_hosts_str = ", ".join([f"{h}:{p}" for h, p in hosts_keys_to_remove])
#         print(f"Attempting to reconnect to: {failed_hosts_str} on next cycle.")


def main():
    global ssh_connections # Allow modification by helper functions

    initialize_connections() # Attempt initial connections

    if not ssh_connections:
        print("Error: Could not establish initial connection to ANY host. Please check config and network. Exiting.")
        sys.exit(1)

    try:
        while True:
            # --- Reconnection Logic ---
            # Get keys of currently active connections
            connected_host_keys = set(ssh_connections.keys())
            # Get keys of all configured hosts
            all_configured_host_keys = {get_host_key(h) for h in hosts}
            # Find which configured hosts are not currently connected
            keys_needing_connection = all_configured_host_keys - connected_host_keys

            if keys_needing_connection:
                reconnect_hosts_str = ", ".join([f"{h}:{p}" for h, p in keys_needing_connection])
                print(f"Attempting to reconnect to missing hosts: {reconnect_hosts_str}")

                for host_key_to_connect in keys_needing_connection:
                    # Find the original host config dictionary matching this key
                    host_config = next((h for h in hosts if get_host_key(h) == host_key_to_connect), None)
                    if host_config:
                        new_ssh = connect_to_host(host_config) # Try to connect
                        if new_ssh:
                            ssh_connections[host_key_to_connect] = new_ssh # Add back if successful
                        # else: connection failed again, will retry next loop

            # --- Update and Print Table ---
            print_dynamic_table()

            # --- Wait ---
            time.sleep(REFRESH_INTERVAL)

    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Exiting.")
    finally:
        # --- Cleanup ---
        close_all_connections()

if __name__ == "__main__":
    main()
