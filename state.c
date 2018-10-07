#include "state.h"

connection_state_t receiver_state_table[CONNECTION_STATE_END][CONNECTION_EVENT_END] = 
{
    [CLOSED] = {
        [OPEN_LISTEN] = LISTEN
    },
    [LISTEN] = {
        [RCVD_SYN] = SYN_RCVD
    },
    [SYN_RCVD] = {
        [SEND_SYNACK] = ESTABLISHED
    },
    [ESTABLISHED] = {
        [RCVD_FIN] = FIN_RCVD
    },
    [FIN_RCVD] = {
        [SEND_FINACK] = CLOSE_WAIT
    },
    [CLOSE_WAIT] = {
        [RCVD_FIN] = FIN_RCVD,
        [MULTI_TIMEOUT_EVENT] = CLOSED
    }
};

connection_state_t sender_state_table[CONNECTION_STATE_END][CONNECTION_EVENT_END] =
{
    [CLOSED] = {
        [SEND_SYN] = SYN_SENT
    },
    [SYN_SENT] = {
        [RCVD_SYNACK] = ESTABLISHED,
        [TIMEOUT_EVENT] = CLOSED,
        [MULTI_TIMEOUT_EVENT] = BROKEN
    },
    [ESTABLISHED] = {
        [SEND_FIN] = FIN_SENT,
    },
    [FIN_SENT] = {
        [RCVD_FINACK] = CLOSED,
        [TIMEOUT_EVENT] = ESTABLISHED,
        [MULTI_TIMEOUT_EVENT] = BROKEN
    }
};

gbn_send_state_t gbn_send_state_table[GBN_SEND_STATE_END][GBN_SEND_EVENT_END] =
{
    [MAKE_AND_SEND] = {
        [SEND_NEW_WIN] = ACKNOWLEDGE
    },
    [ACKNOWLEDGE] = {
        [BASE_NOT_SHIFTED] = RESEND,
        [BASE_SHIFTED] = MAKE_AND_SEND,
    },
    [RESEND] = {
        [RESEND_CUR_WIN] = MAKE_AND_SEND,
        [BASE_SHIFTED] = MAKE_AND_SEND
    }
};

gbn_mode_state_t gbn_mode_state_table[GBN_MODE_STATE_END][GBN_MODE_EVENT_END] =
{
    [SLOW] = {
        [DECELERATE] = SLOW,
        [ACCELERATE] = MODERATE
    },
    [MODERATE] = {
        [DECELERATE] = SLOW,
        [ACCELERATE] = FAST
    },
    [FAST] = {
        [DECELERATE] = SLOW,
        [ACCELERATE] = FAST
    }
};
