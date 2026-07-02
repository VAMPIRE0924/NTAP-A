#ifndef NTAP_A_NODE_SERVER_H
#define NTAP_A_NODE_SERVER_H

#include <stdbool.h>
#include <stddef.h>

#include "a/config.h"

int ntap_a_node_server_run(const ntap_a_config_t *cfg, bool once, int max_sessions,
                           char *err, size_t err_len);

#endif
