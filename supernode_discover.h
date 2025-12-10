#ifndef SUPERNODE_DISCOVERY_H
#define SUPERNODE_DISCOVERY_H

#include "p2p_bot.h"
#include <vector>
#include <string>
#include <map>

// 伙伴节点最大数量
#define MAX_PARTNERS 50

// 发现类型枚举
typedef enum {
    DISCOVERY_TYPE_PARTNER = 1,
    DISCOVERY_TYPE_SUPER_NODE = 2
} DISCOVERY_TYPE;

// 发现请求结构
typedef struct {
    DISCOVERY_TYPE request_type;
    char requester_public_key[KEY_STRING_SIZE + 1];
} DISCOVERY_REQUEST;

// 超级节点配置
typedef struct {
    char node_id[NODE_ID_STRING_SIZE + 1];
    char ip_address[16];
    unsigned short port;
    char public_key[KEY_STRING_SIZE + 1];
    int priority;
    int weight;
} SUPER_NODE_CONFIG;

// 伙伴节点信息
typedef struct {
    char node_id[NODE_ID_STRING_SIZE + 1];
    char ip_address[16];
    unsigned short port;
    char public_key[KEY_STRING_SIZE + 1];
    int distance;
    unsigned long long last_contact;
} PARTNER_NODE;

// 超级节点发现类
class SuperNodeDiscovery {
private:
    std::vector<SUPER_NODE_CONFIG> super_nodes_;
    std::vector<PARTNER_NODE> partner_nodes_;
    std::vector<std::string> network_partitions_;
    CRITICAL_SECTION lock_;
    P2P_CORE* p2p_core_;
    int is_super_node_;
    unsigned int discovery_interval_;
    unsigned int last_partition_check_time_;
    int partition_detection_enabled_;

    void InitializeSuperNodes();
    int CalculateDistance(const char* ip1, unsigned short port1, const char* ip2, unsigned short port2);
    int PingNode(const char* ip, unsigned short port, int timeout_ms);

public:
    SuperNodeDiscovery();
    ~SuperNodeDiscovery();

    int Initialize(P2P_CORE* core);
    void Cleanup();
    int StartDiscovery();
    void StopDiscovery();
    void OnNetworkStatusChange(NETWORK_TYPE new_type, const char* public_ip);
    int AddSuperNode(const char* node_id, const char* ip, unsigned short port,
        const char* pub_key, int priority, int weight);
    std::vector<PARTNER_NODE> GetPartnerNodes(int max_count);
    int ShouldActAsSuperNode();
    int HandlePartnerDiscoveryMessage(const NETWORK_MESSAGE* msg);
    int DetectNetworkPartitions();
    int AttemptPartitionHealing();
};

// 全局实例
extern SuperNodeDiscovery g_supernode_discovery;

// 接口函数
int supernode_discovery_init(P2P_CORE* core);
void supernode_discovery_cleanup();
void supernode_discovery_on_network_change(NETWORK_TYPE net_type, const char* public_ip);
int supernode_discovery_handle_message(const NETWORK_MESSAGE* msg);
int supernode_discovery_start_thread(P2P_CORE* core);
int supernode_discovery_start(P2P_CORE* core); // 别名函数

#endif // SUPERNODE_DISCOVERY_H