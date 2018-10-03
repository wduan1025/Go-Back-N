#ifndef _state_h
#define _state_h

typedef enum
{
    CLOSED = 0,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED, /* 4 */
    FIN_SENT,
    FIN_RCVD,
    CLOSE_WAIT,
    BROKEN,
    CONNECTION_STATE_END
} connection_state_t;

typedef enum
{
    OPEN_LISTEN = 0,
    SEND_SYN,
    RCVD_SYN,
    SEND_SYNACK,
    RCVD_SYNACK,
    SEND_RST,
    SEND_FIN,
    RCVD_FIN,
    SEND_FINACK,
    RCVD_FINACK,
    TIMEOUT_EVENT,
    MULTI_TIMEOUT_EVENT,
    CONNECTION_EVENT_END
} connection_event_t;

typedef enum
{
    MAKE_AND_SEND = 0,
    ACKNOWLEDGE,
    RESEND,
    GBN_SEND_STATE_END
} gbn_send_state_t;

typedef enum
{
    SEND_NEW_WIN = 0,
    BASE_NOT_SHIFTED,
    BASE_SHIFTED,
    RESEND_CUR_WIN,
    GBN_SEND_EVENT_END
} gbn_send_event_t;

typedef enum
{
    SLOW = 0,
    MODERATE,
    FAST,
    GBN_MODE_STATE_END
} gbn_mode_state_t;

typedef enum
{
    ACCELERATE = 0,
    DECELERATE,
    GBN_MODE_EVENT_END
} gbn_mode_event_t;

extern gbn_send_state_t gbn_send_state_table[GBN_SEND_STATE_END][GBN_SEND_EVENT_END];
extern connection_state_t receiver_state_table[CONNECTION_STATE_END][CONNECTION_EVENT_END];
extern connection_state_t sender_state_table[CONNECTION_STATE_END][CONNECTION_EVENT_END];
extern gbn_mode_state_t gbn_mode_state_table[GBN_MODE_STATE_END][GBN_MODE_EVENT_END];

#endif
