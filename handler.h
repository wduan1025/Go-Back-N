#ifndef _timeout_handler_h
#define _timeout_handler_h

void timeout_no_pkt_handler(int sig);
void timeout_wait_synack_handler(int sig);
void timeout_wait_dataack_handler(int sig);
void timeout_wait_finack_handler(int sig);
void timeout_to_close_handler(int sig);

#endif
