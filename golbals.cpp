#include "p2p_bot.h"

// 全局变量定义
P2P_CORE g_p2p_core;
COMMAND_HANDLER g_command_handler;
CRITICAL_SECTION g_nodes_cs;
P2P_NODE g_known_nodes[MAX_NODES];
unsigned int g_node_count = 0;

// 其他全局变量
volatile int g_running = 1;
volatile int g_restart_count = 0;
const int MAX_RESTART_ATTEMPTS = 100;