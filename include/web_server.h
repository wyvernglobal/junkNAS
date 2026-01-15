/*
 * junkNAS - Minimal web server for sharing mountpoint
 */

#ifndef JUNKNAS_WEB_SERVER_H
#define JUNKNAS_WEB_SERVER_H

#include "config.h"

typedef struct junknas_web_server junknas_web_server_t;

junknas_web_server_t *junknas_web_server_start(junknas_config_t *config);
void junknas_web_server_stop(junknas_web_server_t *server);

#endif /* JUNKNAS_WEB_SERVER_H */
