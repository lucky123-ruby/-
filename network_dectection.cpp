#include "p2p_bot.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#include <string>

#define EXTERNAL_TEST_SERVER "8.8.8.8"
#define EXTERNAL_TEST_PORT 53
#define CONNECTION_TIMEOUT 5000

// 使用extern全局变量
extern P2P_CORE g_p2p_core;
extern CRITICAL_SECTION g_nodes_cs;
extern P2P_NODE g_known_nodes[MAX_NODES];
extern unsigned int g_node_count;

// 网络连接类型检测
int network_detect_connection_type(NETWORK_TYPE* net_type, char* public_ip) {
    if (!net_type) return 0;

    // 确保Winsock已经初始化
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[Network] WSAStartup failed: %d\n", WSAGetLastError());
        return 0;
    }

    SOCKET test_socket = INVALID_SOCKET;
    struct sockaddr_in lan_addr, wan_addr;
    fd_set write_fds;
    struct timeval timeout;
    int lan_connected = 0, wan_connected = 0;

    // 初始化地址结构
    memset(&lan_addr, 0, sizeof(lan_addr));
    lan_addr.sin_family = AF_INET;
    lan_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    memset(&wan_addr, 0, sizeof(wan_addr));
    wan_addr.sin_family = AF_INET;
    wan_addr.sin_port = htons(53);

    // 外部测试服务器列表
    const char* test_servers[] = {
        "8.8.8.8",           // Google DNS
        "1.1.1.1",           // Cloudflare DNS
        "208.67.222.222",    // OpenDNS
        "9.9.9.9"           // Quad9 DNS
    };

    // 创建socket
    test_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (test_socket == INVALID_SOCKET) {
        printf("[Network] Failed to create test socket: %d\n", WSAGetLastError());
        WSACleanup();
        *net_type = NET_TYPE_NONE;
        return 0;
    }

    // 设置为非阻塞模式
    unsigned long mode = 1;
    ioctlsocket(test_socket, FIONBIO, &mode);

    // 测试局域网连接
    for (int retry = 1; retry <= 2; retry++) {
        if (connect(test_socket, (struct sockaddr*)&lan_addr, sizeof(lan_addr)) != SOCKET_ERROR) {
            lan_connected = 1;
            break;
        }
        else {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                FD_ZERO(&write_fds);
                FD_SET(test_socket, &write_fds);
                timeout.tv_sec = 3;
                timeout.tv_usec = 0;

                int result = select(0, NULL, &write_fds, NULL, &timeout);
                if (result > 0 && FD_ISSET(test_socket, &write_fds)) {
                    lan_connected = 1;
                    break;
                }
            }
        }
        if (retry < 2) {
            printf("[Network] LAN test attempt %d failed, retrying...\n", retry);
            Sleep(500);
        }
    }

    // 重新创建socket
    closesocket(test_socket);
    test_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ioctlsocket(test_socket, FIONBIO, &mode);

    // 测试外部网络连接
    for (int server_index = 0; server_index < 4; server_index++) {
        inet_pton(AF_INET, test_servers[server_index], &wan_addr.sin_addr);

        printf("[Network] Testing WAN connectivity to %s\n", test_servers[server_index]);

        for (int retry = 1; retry <= 2; retry++) {
            if (connect(test_socket, (struct sockaddr*)&wan_addr, sizeof(wan_addr)) != SOCKET_ERROR) {
                wan_connected = 1;

                // 获取本地IP（可能是NAT后的私有IP）
                struct sockaddr_in local_addr;
                int addr_len = sizeof(local_addr);
                if (getsockname(test_socket, (struct sockaddr*)&local_addr, &addr_len) == 0) {
                    inet_ntop(AF_INET, &local_addr.sin_addr, public_ip, 16);
                    printf("[Network] Connected to internet via %s, local IP: %s\n", test_servers[server_index], public_ip);

                    // 检查是否是私有IP
                    unsigned long ip = ntohl(local_addr.sin_addr.s_addr);
                    if ((ip >= 0x0A000000 && ip <= 0x0AFFFFFF) || // 10.0.0.0/8
                        (ip >= 0xAC100000 && ip <= 0xAC1FFFFF) || // 172.16.0.0/12
                        (ip >= 0xC0A80000 && ip <= 0xC0A8FFFF) || // 192.168.0.0/16
                        (ip >= 0x7F000000 && ip <= 0x7FFFFFFF)) { // 127.0.0.0/8
                        printf("[Network] NAT detected: using private IP %s\n", public_ip);
                        // 将IP标记为NAT，实际外网IP未知
                        strcpy_s(public_ip, sizeof(public_ip), "NAT");
                    }
                }
                break;
            }
            else {
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK) {
                    FD_ZERO(&write_fds);
                    FD_SET(test_socket, &write_fds);
                    timeout.tv_sec = 5;
                    timeout.tv_usec = 0;

                    int result = select(0, NULL, &write_fds, NULL, &timeout);
                    if (result > 0 && FD_ISSET(test_socket, &write_fds)) {
                        wan_connected = 1;

                        // 获取本地IP
                        struct sockaddr_in local_addr;
                        int addr_len = sizeof(local_addr);
                        if (getsockname(test_socket, (struct sockaddr*)&local_addr, &addr_len) == 0) {
                            inet_ntop(AF_INET, &local_addr.sin_addr, public_ip, 16);
                            printf("[Network] Connected to internet via %s, local IP: %s\n", test_servers[server_index], public_ip);

                            // 检查是否是私有IP
                            unsigned long ip = ntohl(local_addr.sin_addr.s_addr);
                            if ((ip >= 0x0A000000 && ip <= 0x0AFFFFFF) ||
                                (ip >= 0xAC100000 && ip <= 0xAC1FFFFF) ||
                                (ip >= 0xC0A80000 && ip <= 0xC0A8FFFF) ||
                                (ip >= 0x7F000000 && ip <= 0x7FFFFFFF)) {
                                printf("[Network] NAT detected: using private IP %s\n", public_ip);
                                strcpy_s(public_ip, sizeof(public_ip), "NAT");
                            }
                        }
                        break;
                    }
                }
            }
            if (retry < 2) {
                printf("[Network] WAN test attempt %d failed for %s, retrying...\n", retry, test_servers[server_index]);
                Sleep(500);
            }
        }

        if (wan_connected) break; // 成功一个就停止
    }

    // 关闭socket
    closesocket(test_socket);
    WSACleanup();

    // 检测结果
    if (lan_connected && wan_connected) {
        if (strcmp(public_ip, "NAT") == 0) {
            *net_type = NET_TYPE_BOTH; // 虽然通过NAT但能连通外网
        }
        else {
            *net_type = NET_TYPE_BOTH;
        }
        printf("[Network] Network type: Both LAN and WAN, Public IP: %s\n", public_ip);
    }
    else if (lan_connected) {
        *net_type = NET_TYPE_LAN_ONLY;
        printf("[Network] Network type: LAN Only\n");
    }
    else if (wan_connected) {
        if (strcmp(public_ip, "NAT") == 0) {
            *net_type = NET_TYPE_WAN_ONLY; // 实际通过NAT连接外网
        }
        else {
            *net_type = NET_TYPE_WAN_ONLY;
        }
        printf("[Network] Network type: WAN Only, Public IP: %s\n", public_ip);
    }
    else {
        *net_type = NET_TYPE_NONE;
        printf("[Network] Network type: No Network\n");
    }

    return 1;
}

// 广播网络状态信息
void network_broadcast_status(P2P_CORE* core) {
    if (!core) return;

    NETWORK_STATUS status;
    NETWORK_TYPE net_type;
    char public_ip[16] = { 0 };

    if (network_detect_connection_type(&net_type, public_ip)) {
        status.net_type = net_type;
        strcpy_s(status.public_ip, sizeof(status.public_ip), public_ip);
        status.timestamp = get_timestamp();

        // 构建状态广播消息
        NETWORK_MESSAGE status_msg;
        memset(&status_msg, 0, sizeof(NETWORK_MESSAGE));

        generate_message_id(status_msg.message_id);
        strcpy_s(status_msg.sender_id, sizeof(status_msg.sender_id), core->node_id);
        status_msg.message_type = MSG_TYPE_DISCOVERY;
        status_msg.timestamp = get_timestamp();
        status_msg.encrypted = 0;

        memcpy(status_msg.data, &status, sizeof(NETWORK_STATUS));
        status_msg.data_size = sizeof(NETWORK_STATUS);

        // 广播网络状态信息
        p2p_broadcast_message(core, &status_msg);

        printf("[Network] Broadcast network status: type=%d, ip=%s\n",
            status.net_type, status.public_ip);

        // 通知超级节点发现模块网络状态变化
        supernode_discovery_on_network_change(net_type, public_ip);
    }
    else {
        printf("[Network] Failed to detect network status for broadcast\n");
    }
}

// 处理网络状态信息
void p2p_handle_network_status(P2P_CORE* core, const NETWORK_MESSAGE* msg) {
    if (!core || !msg || msg->data_size != sizeof(NETWORK_STATUS)) return;

    NETWORK_STATUS status;
    memcpy(&status, msg->data, sizeof(NETWORK_STATUS));

    // 更新已知节点状态
    EnterCriticalSection(&g_nodes_cs);

    for (unsigned int i = 0; i < g_node_count; i++) {
        if (strcmp(g_known_nodes[i].node_id, msg->sender_id) == 0) {
            printf("[Network] Node %s network status: type=%d, public_ip=%s\n",
                msg->sender_id, status.net_type, status.public_ip);

            // 可以扩展P2P_NODE结构存储状态信息
            break;
        }
    }

    LeaveCriticalSection(&g_nodes_cs);
}

// 网络状态监控线程
unsigned __stdcall network_status_thread(void* param) {
    P2P_CORE* core = (P2P_CORE*)param;

    if (!core) {
        printf("[NetworkStatus] Error: Invalid core pointer\n");
        return 0;
    }

    printf("[NetworkStatus] Network status monitoring thread started\n");

    unsigned int loop_count = 0;
    NETWORK_TYPE last_net_type = NET_TYPE_NONE;
    char last_public_ip[16] = { 0 };

    while (core->running) {
        Sleep(1000);
        loop_count++;

        // 每5分钟广播一次状态
        if (loop_count % 300 == 0) {
            network_broadcast_status(core);
        }

        // 每30秒检测状态变化
        if (loop_count % 30 == 0) {
            NETWORK_TYPE current_net_type;
            char current_public_ip[16] = { 0 };

            if (network_detect_connection_type(&current_net_type, current_public_ip)) {
                if (current_net_type != last_net_type ||
                    strcmp(current_public_ip, last_public_ip) != 0) {

                    printf("[NetworkStatus] Network status changed, broadcasting update\n");
                    printf("[NetworkStatus] Old: type=%d, ip=%s\n", last_net_type, last_public_ip);
                    printf("[NetworkStatus] New: type=%d, ip=%s\n", current_net_type, current_public_ip);

                    network_broadcast_status(core);

                    last_net_type = current_net_type;
                    strcpy_s(last_public_ip, sizeof(last_public_ip), current_public_ip);
                }
            }
        }
    }

    printf("[NetworkStatus] Network status monitoring thread exited\n");
    return 1;
}

// 启动网络状态监控
int network_status_start(P2P_CORE* core) {
    if (!core || !core->running) return 0;

    HANDLE status_thread = (HANDLE)_beginthreadex(NULL, 0, network_status_thread, core, 0, NULL);
    if (!status_thread) {
        printf("[NetworkStatus] Failed to create network status thread\n");
        return 0;
    }

    CloseHandle(status_thread); // 线程句柄不需要保持
    printf("[NetworkStatus] Network status monitoring started\n");
    return 1;
}