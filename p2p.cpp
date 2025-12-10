#include "p2p_bot.h"
#include <stdio.h>

// 删除重复的全局变量定义，使用extern声明的全局变量

// ==============================================
// New helper function implementations
// ==============================================

/**
 * @brief Get local IP address
 */
int get_local_ip(char* ip_buffer) {
    if (!ip_buffer) return 0;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[IP Get] WSAStartup failed: %d\n", WSAGetLastError());
        return 0;
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        printf("[IP Get] Failed to get hostname: %d\n", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    struct hostent* hostinfo = gethostbyname(hostname);
    if (hostinfo == NULL) {
        printf("[IP Get] Failed to get host information\n");
        WSACleanup();
        return 0;
    }

    if (hostinfo->h_addr_list[0] != NULL) {
        struct in_addr addr;
        memcpy(&addr, hostinfo->h_addr_list[0], sizeof(struct in_addr));
        const char* ip_str = inet_ntoa(addr);
        if (ip_str) {
            strcpy_s(ip_buffer, 16, ip_str);
            WSACleanup();
            return 1;
        }
    }

    WSACleanup();
    return 0;
}

/**
 * @brief Calculate subnet broadcast address
 */
int calculate_broadcast_address(const char* local_ip, const char* subnet_mask, char* broadcast_ip) {
    if (!local_ip || !broadcast_ip) return 0;

    // Use common mask if no subnet mask provided
    const char* mask = subnet_mask;
    if (!mask) {
        // Select default mask based on IP address type
        if (strncmp(local_ip, "192.168.", 8) == 0) {
            mask = "255.255.255.0";
        }
        else if (strncmp(local_ip, "10.", 3) == 0) {
            mask = "255.0.0.0";
        }
        else if (strncmp(local_ip, "172.", 4) == 0) {
            // Check if in range 172.16.0.0-172.31.255.255
            int second_octet = atoi(local_ip + 4);
            if (second_octet >= 16 && second_octet <= 31) {
                mask = "255.255.0.0";
            }
            else {
                mask = "255.255.255.0";
            }
        }
        else {
            mask = "255.255.255.0"; // Default to /24 mask
        }
    }

    struct in_addr ip_addr, mask_addr, broadcast_addr;

    if (inet_pton(AF_INET, local_ip, &ip_addr) != 1) {
        printf("[Broadcast Address] Invalid IP address: %s\n", local_ip);
        return 0;
    }

    if (inet_pton(AF_INET, mask, &mask_addr) != 1) {
        printf("[Broadcast Address] Invalid subnet mask: %s\n", mask);
        return 0;
    }

    // Calculate broadcast address: IP OR (NOT Mask)
    broadcast_addr.s_addr = ip_addr.s_addr | ~mask_addr.s_addr;

    const char* result = inet_ntoa(broadcast_addr);
    if (result) {
        strcpy_s(broadcast_ip, 16, result);
        return 1;
    }

    return 0;
}

// ==============================================
// Network thread function (fixed version)
// ==============================================

unsigned __stdcall network_thread(void* param) {
    P2P_CORE* core = (P2P_CORE*)param;

    if (!core) {
        printf("[Network] Error: Network thread received null core pointer\n");
        return 0;
    }

    printf("[Network] Network thread started, core pointer: %p\n", core);
    printf("[Network] Port: %d, initial running state: %d\n", core->listen_port, core->running);

    struct sockaddr_in server_addr, client_addr;
    int addr_len = sizeof(client_addr);
    char buffer[MAX_PACKET_SIZE];
    SOCKET listen_socket = INVALID_SOCKET;

    printf("[Network] Preparing to create socket, port: %d\n", core->listen_port);

    // Create socket
    listen_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket == INVALID_SOCKET) {
        printf("[Network] Socket creation failed: %d\n", WSAGetLastError());
        return 0;
    }
    printf("[Network] Socket created successfully: %d\n", listen_socket);

    // Set broadcast option (fixed: added detailed error checking)
    int broadcast = 1;
    if (setsockopt(listen_socket, SOL_SOCKET, SO_BROADCAST,
        (char*)&broadcast, sizeof(broadcast)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        printf("[Network] Failed to set broadcast option: %d\n", error);

        // Provide specific suggestions based on error code
        switch (error) {
        case WSAEACCES:
            printf("[Network] Insufficient permissions, please run as administrator\n");
            break;
        case WSAENOPROTOOPT:
            printf("[Network] Protocol option not supported\n");
            break;
        default:
            break;
        }
        closesocket(listen_socket);
        return 0;
    }
    printf("[Network] Broadcast option set successfully\n");

    // Set address reuse
    int reuse = 1;
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
        (char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
        printf("[Network] Failed to set address reuse: %d\n", WSAGetLastError());
    }
    else {
        printf("[Network] Address reuse set successfully\n");
    }

    // Bind address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(core->listen_port);

    if (bind(listen_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("[Network] Failed to bind port %d: %d\n", core->listen_port, WSAGetLastError());
        closesocket(listen_socket);
        return 0;
    }
    printf("[Network] Port bound successfully: %d\n", core->listen_port);

    // Update socket in core structure
    core->listen_socket = listen_socket;
    printf("[Network] Socket set to core structure, starting to listen...\n");

    // Main loop
    while (core->running) {
        fd_set readfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_SET(listen_socket, &readfds);

        timeout.tv_sec = 1;  // 1 second timeout
        timeout.tv_usec = 0;

        // Use select to avoid blocking
        int select_result = select(0, &readfds, NULL, NULL, &timeout);

        if (select_result == SOCKET_ERROR) {
            printf("[Network] select error: %d\n", WSAGetLastError());
            break;
        }

        if (select_result > 0 && FD_ISSET(listen_socket, &readfds)) {
            int bytes_received = recvfrom(listen_socket, buffer, MAX_PACKET_SIZE, 0,
                (struct sockaddr*)&client_addr, &addr_len);

            if (bytes_received > 0 && bytes_received >= (int)sizeof(NETWORK_MESSAGE)) {
                NETWORK_MESSAGE* msg = (NETWORK_MESSAGE*)buffer;
                printf("[Network] Received message, type: %d, size: %d bytes\n", msg->message_type, bytes_received);
                p2p_handle_message(core, msg, &client_addr);
            }
            else if (bytes_received > 0) {
                printf("[Network] Received invalid message, size: %d bytes\n", bytes_received);
            }
            else if (bytes_received == 0) {
                printf("[Network] Connection closed\n");
            }
            else {
                int error = WSAGetLastError();
                if (error != WSAEWOULDBLOCK) {
                    printf("[Network] Receive error: %d\n", error);
                }
            }
        }

        // Brief sleep to avoid high CPU usage
        Sleep(10);
    }

    // Cleanup
    printf("[Network] Network thread exiting, cleaning resources...\n");
    closesocket(listen_socket);
    core->listen_socket = INVALID_SOCKET;

    printf("[Network] Network thread exit completed\n");
    return 1;
}

// ==============================================
// Node discovery thread (fixed version)
// ==============================================

unsigned __stdcall discovery_thread(void* param) {
    P2P_CORE* core = (P2P_CORE*)param;

    if (!core) {
        printf("[Discovery] Error: Discovery thread received null core pointer\n");
        return 0;
    }

    printf("[Discovery] Node discovery thread started\n");

    // 等待网络socket就绪
    int wait_attempts = 0;
    while (core->running && core->listen_socket == INVALID_SOCKET) {
        if (wait_attempts++ > 100) {
            printf("[Discovery] Network thread initialization timeout\n");
            return 0;
        }
        Sleep(100);
    }

    if (!core->running) {
        printf("[Discovery] Network stopped, discovery thread exiting\n");
        return 0;
    }

    unsigned int loop_count = 0;
    while (core->running) {
        // 创建精简的发现消息（减小大小）
        NETWORK_MESSAGE discovery_msg;
        memset(&discovery_msg, 0, sizeof(NETWORK_MESSAGE));

        generate_message_id(discovery_msg.message_id);
        strcpy_s(discovery_msg.sender_id, sizeof(discovery_msg.sender_id), core->node_id);
        discovery_msg.message_type = MSG_TYPE_DISCOVERY;
        discovery_msg.timestamp = get_timestamp();
        discovery_msg.encrypted = 0;
        discovery_msg.data_size = 0;  // 发现消息不需要数据

        // 计算实际发送大小（只发送必要字段）
        size_t send_size = offsetof(NETWORK_MESSAGE, data);  // 只发送到data字段之前

        struct sockaddr_in broadcast_addr;
        memset(&broadcast_addr, 0, sizeof(broadcast_addr));
        broadcast_addr.sin_family = AF_INET;
        broadcast_addr.sin_port = htons(core->listen_port);

        // 获取广播地址
        char local_ip[16] = { 0 };
        char broadcast_ip[16] = { 0 };

        if (get_local_ip(local_ip) && calculate_broadcast_address(local_ip, NULL, broadcast_ip)) {
            printf("[Discovery] Using subnet broadcast: %s\n", broadcast_ip);
            broadcast_addr.sin_addr.s_addr = inet_addr(broadcast_ip);
        }
        else {
            printf("[Discovery] Using global broadcast: 255.255.255.255\n");
            broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
        }

        // 发送消息（使用减小后的尺寸）
        if (core->listen_socket != INVALID_SOCKET) {
            int send_result = sendto(core->listen_socket, (char*)&discovery_msg,
                (int)send_size, 0,  // 只发送必要部分
                (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

            if (send_result == SOCKET_ERROR) {
                int error = WSAGetLastError();
                // 忽略10040错误（消息过大），继续运行
                if (error != WSAEMSGSIZE) {
                    printf("[Discovery] Send error %d (size: %zu)\n", error, send_size);
                }
            }
            else {
                printf("[Discovery] Message sent successfully (size: %d bytes)\n", send_result);
            }
        }

        loop_count++;

        // 每30秒发送一次
        for (int i = 0; i < 30 && core->running; i++) {
            Sleep(1000);
        }
    }

    printf("[Discovery] Discovery thread exited\n");
    return 1;
}

// ==============================================
// Original function implementations (unchanged)
// ==============================================

// P2P initialization
int p2p_initialize(P2P_CORE* core, NODE_TYPE node_type, unsigned short port) {
    if (!core) {
        printf("[Initialization] Error: Null core pointer passed\n");
        return 0;
    }

    // Completely zero the structure
    memset(core, 0, sizeof(P2P_CORE));

    // Initialize basic members first
    core->current_type = node_type;
    core->current_state = NODE_STATE_OFFLINE;
    core->listen_port = port;
    core->running = 0;
    core->listen_socket = INVALID_SOCKET;

    printf("[Initialization] Starting Winsock initialization...\n");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[Initialization] WSAStartup failed: %d\n", WSAGetLastError());
        return 0;
    }

    // First generate node ID
    printf("[Initialization] Generating node ID...\n");
    generate_node_id(core->node_id);

    // Verify node ID generation result
    size_t node_id_len = strlen(core->node_id);
    if (node_id_len == 0) {
        printf("[Initialization] Error: Node ID generation failed\n");
        WSACleanup();
        return 0;
    }

    if (node_id_len != NODE_ID_STRING_SIZE) {
        printf("[Initialization] Warning: Abnormal node ID length (%zu != %d)\n", node_id_len, NODE_ID_STRING_SIZE);
    }

    printf("[Initialization] Node ID: %s (length: %zu)\n", core->node_id, node_id_len);

    // Generate encryption key pair
    printf("[Initialization] Generating encryption key pair...\n");
    unsigned char pub_key[PUBLIC_KEY_BINARY_SIZE] = { 0 };
    unsigned char priv_key[PRIVATE_KEY_BINARY_SIZE] = { 0 };
    if (!crypto_generate_keypair(pub_key, priv_key)) {
        printf("[Initialization] Key pair generation failed\n");
        WSACleanup();
        return 0;
    }

    printf("[Initialization] Initializing encryption module...\n");
    if (!crypto_init(&core->crypto_ctx)) {
        printf("[Initialization] Encryption module initialization failed\n");
        WSACleanup();
        return 0;
    }

    // Encode keys
    hex_encode(pub_key, PUBLIC_KEY_BINARY_SIZE, core->public_key);
    hex_encode(priv_key, PRIVATE_KEY_BINARY_SIZE, core->private_key);

    // Initialize critical section
    InitializeCriticalSection(&g_nodes_cs);

    printf("[Initialization] P2P node initialization completed\n");
    printf("[Initialization] Node type: %s\n", node_type == NODE_TYPE_SUPER ? "Super Node" : "Normal Node");
    printf("[Initialization] Listening port: %d\n", port);

    return 1;
}

// Cleanup P2P resources
void p2p_cleanup(P2P_CORE* core) {
    if (!core) return;

    printf("[Cleanup] Cleaning up P2P resources...\n");

    // Stop network thread
    p2p_stop_network(core);

    // Cleanup encryption context
    crypto_cleanup(&core->crypto_ctx);

    // Cleanup critical section for known nodes list
    DeleteCriticalSection(&g_nodes_cs);

    // Cleanup WSA
    WSACleanup();

    printf("[Cleanup] P2P resource cleanup completed\n");
}

// Start network
int p2p_start_network(P2P_CORE* core) {
    if (!core) {
        printf("[Network] Error: Null core pointer passed\n");
        return 0;
    }

    printf("[Network] Starting network service, port: %d\n", core->listen_port);

    // Ensure running flag is set
    core->running = 1;
    printf("[Network] Set core running flag: %d\n", core->running);

    // First create network thread
    HANDLE network_thread_handle = (HANDLE)_beginthreadex(NULL, 0, network_thread, core, 0, NULL);
    if (!network_thread_handle) {
        printf("[Network] Network thread creation failed\n");
        core->running = 0;
        return 0;
    }

    // Wait for network thread to complete socket initialization (max 10 seconds)
    printf("[Network] Waiting for network thread to initialize socket...\n");
    int wait_count = 0;
    while (core->listen_socket == INVALID_SOCKET && wait_count < 100 && core->running) {
        if (wait_count % 10 == 0) {  // Print every 1 second
            printf("[Network] Waiting for socket initialization... (%d/100)\n", wait_count);
        }
        Sleep(100);
        wait_count++;
    }

    if (core->listen_socket == INVALID_SOCKET) {
        printf("[Network] Network thread initialization timeout, socket still not ready\n");
        core->running = 0;
        WaitForSingleObject(network_thread_handle, 3000);
        CloseHandle(network_thread_handle);
        return 0;
    }

    printf("[Network] Network thread initialization completed, socket is ready: %d\n", core->listen_socket);

    // Now start discovery thread (socket is now valid)
    HANDLE discovery_thread_handle = (HANDLE)_beginthreadex(NULL, 0, discovery_thread, core, 0, NULL);
    if (!discovery_thread_handle) {
        printf("[Network] Discovery thread creation failed\n");
        core->running = 0;
        WaitForSingleObject(network_thread_handle, 3000);
        CloseHandle(network_thread_handle);
        return 0;
    }

    printf("[Network] Discovery thread created successfully\n");

    // Save thread handles to global variables
    static HANDLE g_network_thread = NULL;
    static HANDLE g_discovery_thread = NULL;
    static int g_threads_running = 0;

    g_network_thread = network_thread_handle;
    g_discovery_thread = discovery_thread_handle;
    g_threads_running = 1;

    printf("[Network] Network service started successfully, port: %d\n", core->listen_port);
    return 1;
}

// ==============================================
// Stop network
// ==============================================

void p2p_stop_network(P2P_CORE* core) {
    if (!core) return;

    printf("[Network] Stopping network...\n");
    core->running = 0;
    core->current_state = NODE_STATE_OFFLINE;

    static HANDLE g_network_thread = NULL;
    static HANDLE g_discovery_thread = NULL;
    static int g_threads_running = 0;

    if (g_threads_running) {
        if (g_discovery_thread) {
            WaitForSingleObject(g_discovery_thread, 5000);
            CloseHandle(g_discovery_thread);
            g_discovery_thread = NULL;
        }

        if (g_network_thread) {
            WaitForSingleObject(g_network_thread, 5000);
            CloseHandle(g_network_thread);
            g_network_thread = NULL;
        }

        g_threads_running = 0;
    }

    printf("[Network] Network stopped\n");
}

// ==============================================
// Broadcast message
// ==============================================

int p2p_broadcast_message(P2P_CORE* core, const NETWORK_MESSAGE* msg) {
    if (!core || !msg) return 0;

    EnterCriticalSection(&g_nodes_cs);

    int sent_count = 0;
    int total_nodes = g_node_count;

    printf("[Broadcast] Broadcasting message type %d to %d nodes\n", msg->message_type, total_nodes);

    for (unsigned int i = 0; i < g_node_count; i++) {
        if (g_known_nodes[i].state == NODE_STATE_ONLINE) {
            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;

            // 使用现代inet_pton函数替代已弃用的inet_addr
            if (inet_pton(AF_INET, g_known_nodes[i].ip_address, &target_addr.sin_addr) != 1) {
                printf("[Broadcast] Invalid IP address: %s\n", g_known_nodes[i].ip_address);
                continue;
            }
            target_addr.sin_port = htons(g_known_nodes[i].port);

            int result = sendto(core->listen_socket, (const char*)msg, sizeof(NETWORK_MESSAGE), 0,
                (struct sockaddr*)&target_addr, sizeof(target_addr));

            if (result != SOCKET_ERROR) {
                sent_count++;
                if (sent_count <= 5) { // 只记录前5个成功发送，避免日志过多
                    printf("[Broadcast] Successfully sent to node: %s:%d\n",
                        g_known_nodes[i].ip_address, g_known_nodes[i].port);
                }
            }
            else {
                int error = WSAGetLastError();
                if (error != WSAENETUNREACH && error != WSAEHOSTUNREACH) {
                    printf("[Broadcast] Failed to send to node %s:%d: %d\n",
                        g_known_nodes[i].ip_address, g_known_nodes[i].port, error);
                }

                // 如果发送失败，标记节点为离线
                g_known_nodes[i].state = NODE_STATE_OFFLINE;
            }
        }
    }

    // 如果没有已知节点，尝试子网广播
    if (total_nodes == 0) {
        printf("[Broadcast] No known nodes, attempting subnet broadcast\n");

        char local_ip[16] = { 0 };
        char broadcast_ip[16] = { 0 };

        if (get_local_ip(local_ip) && calculate_broadcast_address(local_ip, NULL, broadcast_ip)) {
            struct sockaddr_in broadcast_addr;
            memset(&broadcast_addr, 0, sizeof(broadcast_addr));
            broadcast_addr.sin_family = AF_INET;
            broadcast_addr.sin_port = htons(core->listen_port);
            inet_pton(AF_INET, broadcast_ip, &broadcast_addr.sin_addr);

            int result = sendto(core->listen_socket, (const char*)msg, sizeof(NETWORK_MESSAGE), 0,
                (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));

            if (result != SOCKET_ERROR) {
                sent_count++;
                printf("[Broadcast] Subnet broadcast sent to %s:%d\n", broadcast_ip, core->listen_port);
            }
            else {
                printf("[Broadcast] Subnet broadcast failed: %d\n", WSAGetLastError());
            }
        }
    }

    LeaveCriticalSection(&g_nodes_cs);

    if (sent_count > 0) {
        printf("[Broadcast] Successfully sent messages to %d/%d nodes\n", sent_count, total_nodes);
    }
    else {
        printf("[Broadcast] No messages successfully sent to any nodes\n");
    }

    return sent_count > 0;
}

// ==============================================
// Handle ping message
// ==============================================

void p2p_handle_ping(P2P_CORE* core, const NETWORK_MESSAGE* msg, struct sockaddr_in* from_addr) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from_addr->sin_addr, ip_str, INET_ADDRSTRLEN);

    printf("[Network] Received PING message from: %s (%s:%d)\n",
        msg->sender_id, ip_str, ntohs(from_addr->sin_port));

    // Send pong response
    NETWORK_MESSAGE pong_msg = { 0 };
    generate_message_id(pong_msg.message_id);
    strcpy_s(pong_msg.sender_id, sizeof(pong_msg.sender_id), core->node_id);
    strcpy_s(pong_msg.recipient_id, sizeof(pong_msg.recipient_id), msg->sender_id);
    pong_msg.message_type = MSG_TYPE_PONG;
    pong_msg.timestamp = get_timestamp();
    pong_msg.encrypted = 0;

    int result = sendto(core->listen_socket, (char*)&pong_msg, sizeof(pong_msg), 0,
        (struct sockaddr*)from_addr, sizeof(struct sockaddr_in));

    if (result != SOCKET_ERROR) {
        printf("[Network] PONG response sent successfully\n");
    }
    else {
        printf("[Network] PONG response send failed: %d\n", WSAGetLastError());
    }
}

// ==============================================
// Handle discovery message
// ==============================================

void p2p_handle_discovery(P2P_CORE* core, const NETWORK_MESSAGE* msg, struct sockaddr_in* from_addr) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from_addr->sin_addr, ip_str, INET_ADDRSTRLEN);
    unsigned short port = ntohs(from_addr->sin_port);

    printf("[Discovery] Discovered new node: %s (%s:%d)\n", msg->sender_id, ip_str, port);

    EnterCriticalSection(&g_nodes_cs);

    int exists = 0;
    for (unsigned int i = 0; i < g_node_count; i++) {
        if (strcmp(g_known_nodes[i].node_id, msg->sender_id) == 0) {
            printf("[Discovery] Updating known node: %s -> %s:%d\n", msg->sender_id, ip_str, port);
            strcpy_s(g_known_nodes[i].ip_address, sizeof(g_known_nodes[i].ip_address), ip_str);
            g_known_nodes[i].port = port;
            g_known_nodes[i].last_seen = get_timestamp();
            exists = 1;
            break;
        }
    }

    if (!exists && g_node_count < MAX_NODES) {
        P2P_NODE* node = &g_known_nodes[g_node_count];
        strcpy_s(node->node_id, sizeof(node->node_id), msg->sender_id);
        strcpy_s(node->ip_address, sizeof(node->ip_address), ip_str);
        node->port = port;
        node->node_type = NODE_TYPE_SLAVE;
        node->state = NODE_STATE_ONLINE;
        node->last_seen = get_timestamp();
        g_node_count++;

        printf("[Discovery] New node added to list, current node count: %d\n", g_node_count);
    }
    else if (g_node_count >= MAX_NODES) {
        printf("[Discovery] Node list is full, cannot add new node\n");
    }

    LeaveCriticalSection(&g_nodes_cs);
}

// ==============================================
// Check if can become super node
// ==============================================

int p2p_can_become_super_node(const P2P_CORE* core) {
    if (!core) return 0;

    // Simple check: if memory > 2GB and currently normal node, can upgrade
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);
    if (GlobalMemoryStatusEx(&memory_status)) {
        int can_upgrade = (memory_status.ullTotalPhys > 2ULL * 1024 * 1024 * 1024) &&
            (core->current_type == NODE_TYPE_SLAVE);
        return can_upgrade;
    }

    return 0;
}

// ==============================================
// Promote to super node
// ==============================================

int p2p_promote_to_super_node(P2P_CORE* core) {
    if (!core) return 0;

    if (core->current_type == NODE_TYPE_SUPER) {
        printf("[Upgrade] Already a super node\n");
        return 1;
    }

    printf("[Upgrade] Promoting node to super node\n");
    core->current_type = NODE_TYPE_SUPER;

    // Can add special initialization code for super nodes here
    printf("[Upgrade] Node successfully upgraded to super node\n");

    return 1;
}

// ==============================================
// Handle message (主要实现)
// ==============================================

void p2p_handle_message(P2P_CORE* core, const NETWORK_MESSAGE* msg, struct sockaddr_in* from_addr) {
    if (!core || !msg || !from_addr) return;

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from_addr->sin_addr, ip_str, INET_ADDRSTRLEN);
    unsigned short port = ntohs(from_addr->sin_port);

    printf("[Network] Processing message from %s:%d, type: %d, size: %d bytes\n",
        ip_str, port, msg->message_type, msg->data_size);

    NETWORK_MESSAGE processed_msg = *msg;

    // 消息解密
    if (msg->encrypted) {
        unsigned char decrypted_data[MAX_PACKET_SIZE] = { 0 };
        unsigned int decrypted_size = MAX_PACKET_SIZE;

        if (crypto_decrypt(&core->crypto_ctx, msg->data, msg->data_size,
            decrypted_data, &decrypted_size)) {
            memcpy(processed_msg.data, decrypted_data, decrypted_size);
            processed_msg.data_size = decrypted_size;
            printf("[Network] Message decrypted successfully\n");
        }
        else {
            printf("[Network] Message decryption failed\n");
            return; // 解密失败，丢弃消息
        }
    }

    // 更新或添加发送者到已知节点列表
    EnterCriticalSection(&g_nodes_cs);
    int node_exists = 0;
    for (unsigned int i = 0; i < g_node_count; i++) {
        if (strcmp(g_known_nodes[i].node_id, msg->sender_id) == 0) {
            // 更新现有节点信息
            strcpy_s(g_known_nodes[i].ip_address, sizeof(g_known_nodes[i].ip_address), ip_str);
            g_known_nodes[i].port = port;
            g_known_nodes[i].state = NODE_STATE_ONLINE;
            g_known_nodes[i].last_seen = get_timestamp();
            node_exists = 1;
            break;
        }
    }

    if (!node_exists && g_node_count < MAX_NODES) {
        // 添加新节点
        P2P_NODE* new_node = &g_known_nodes[g_node_count];
        strcpy_s(new_node->node_id, sizeof(new_node->node_id), msg->sender_id);
        strcpy_s(new_node->ip_address, sizeof(new_node->ip_address), ip_str);
        new_node->port = port;
        new_node->node_type = NODE_TYPE_SLAVE; // 默认为普通节点
        new_node->state = NODE_STATE_ONLINE;
        new_node->last_seen = get_timestamp();
        g_node_count++;

        printf("[Network] New node added: %s (%s:%d), total nodes: %u\n",
            msg->sender_id, ip_str, port, g_node_count);
    }
    LeaveCriticalSection(&g_nodes_cs);

    // 根据消息类型处理
    switch (msg->message_type) {
    case MSG_TYPE_PING:
        printf("[Network] Processing PING message\n");
        p2p_handle_ping(core, &processed_msg, from_addr);
        break;

    case MSG_TYPE_DISCOVERY:
        // 根据数据大小判断是网络状态还是节点发现
        if (processed_msg.data_size == sizeof(NETWORK_STATUS)) {
            printf("[Network] Processing NETWORK_STATUS message\n");
            p2p_handle_network_status(core, &processed_msg);
        }
        else {
            printf("[Network] Processing DISCOVERY message\n");

            // 先尝试超级节点发现处理
            if (supernode_discovery_handle_message(&processed_msg)) {
                printf("[SuperNode] Discovery message handled by super node module\n");
            }
            else {
                // 如果超级节点发现没有处理，则使用默认发现处理
                p2p_handle_discovery(core, &processed_msg, from_addr);
            }
        }
        break;

    case MSG_TYPE_COMMAND:
        printf("[Command] Received command message\n");
        command_handler_process_message(&g_command_handler, &processed_msg);
        break;

    case MSG_TYPE_HEARTBEAT:
        printf("[Heartbeat] Received heartbeat message\n");
        // 更新节点最后活动时间
        break;

    case FILE_CHUNK:
        printf("[FileTransfer] Received FILE_CHUNK message\n");
        p2p_handle_file_transfer(core, &processed_msg);
        break;

    default:
        printf("[Network] Received unknown type message: %d\n", msg->message_type);
        break;
    }
}