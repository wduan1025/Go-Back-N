#include "handler.h"
#include "gbn.h"

int timeout_synack_count = 0;
int timeout_finack_count = 0;

/* if time out, change state to CLOSED or BROKEN*/
void timeout_wait_synack_handler(int sig)
{
    log_info("[timeout_wait_synack_handler] Entering");
    log_debug("[timeout_wait_synack_handler] change from state SYN_SENT to CLOSED to resend SYN");
    timeout_synack_count++;
    if (timeout_synack_count == MAX_TIMEOUT_COUNT * TIMEOUT)
    {
        host_session.cur_state = lookup_connect_transit(&host_session, MULTI_TIMEOUT_EVENT);
    }
    else
    {
        host_session.cur_state = lookup_connect_transit(&host_session, TIMEOUT_EVENT);
    }
}

void timeout_wait_dataack_handler(int sig)
{
    log_info("[timeout_wait_dataack_handler] Entering");

    gbn_send_session.cur_state = lookup_gbn_send_transit(&gbn_send_session, BASE_NOT_SHIFTED);
}

/* if time out, FIN_SENT change state to ESTABLISHED */
void timeout_wait_finack_handler(int sig)
{
    log_info("[timeout_wait_finack_handler] Entering");
    timeout_finack_count++;
    if (timeout_finack_count == MAX_TIMEOUT_COUNT * TIMEOUT)
    {
        host_session.cur_state = lookup_connect_transit(&host_session, MULTI_TIMEOUT_EVENT);
    }
    else
    {
        host_session.cur_state = lookup_connect_transit(&host_session, TIMEOUT_EVENT);
    }
}

void timeout_to_close_handler(int sig)
{
    log_info("[timeout_to_close_handler] Entering");

    host_session.cur_state = lookup_connect_transit(&host_session, MULTI_TIMEOUT_EVENT);
    log_info("[timeout_to_close_handler] Current state CLOSED(0): %d", host_session.cur_state);
    log_info("[timeout_to_close_handler] The connection is going to be gracefully closed");
}
