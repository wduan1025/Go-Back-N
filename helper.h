#ifndef _helper_h
#define _helper_h

#include "state.h"
#include "gbn.h"

connection_state_t lookup_connect_transit(host_session_t *host_session, connection_event_t event);
gbn_mode_state_t lookup_gbn_mode_transit(gbn_mode_session_t *gbn_mode_session, gbn_mode_event_t event);
gbn_send_state_t lookup_gbn_send_transit(gbn_send_session_t *gbn_send_session, gbn_send_event_t event);
ssize_t sendto_host(host_session_t *host, struct gbnhdr *packet);
ssize_t recvfrom_host(host_session_t *host, struct gbnhdr *packet);
struct gbnhdr make_pkt(uint8_t pkt_type, uint8_t seqnum, uint8_t *data, uint64_t datalen);
uint8_t has_seqnum(struct gbnhdr *packet, uint8_t seqnum);
int window_not_full(int base, int seqnum, int window_size);
int validate_checksum(struct gbnhdr packet);
uint16_t checksum(uint8_t *buf, int nwords);
ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);

#endif
