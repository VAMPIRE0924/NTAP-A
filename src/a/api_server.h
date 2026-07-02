#ifndef NTAP_A_API_SERVER_H
#define NTAP_A_API_SERVER_H

#include <stdbool.h>
#include <stddef.h>

#include "a/config.h"

int ntap_a_api_server_run(const ntap_a_config_t *cfg, bool once, int max_requests,
                          char *err, size_t err_len);

#endif
