#include "helper.h"
connection_state_t lookup_connect_transit(host_session_t *host_session, connection_event_t event)
{
    if (host_session->cur_state >= CONNECTION_STATE_END || event >= CONNECTION_EVENT_END || host_session->cur_state < 0 || event < 0)
    {
        log_error("[lookup_connect_transit] Invalid arguments");
        return -1;
    }

    log_info("[lookup_connect_transit] prev state = %d", host_session->cur_state);
    log_debug("[lookup_connect_transit] Inputting event = %d", event);

    if (host_session->host_type == RECEIVER)
    {
        return receiver_state_table[host_session->cur_state][event];
    }

    if (host_session->host_type == SENDER)
    {
        return sender_state_table[host_session->cur_state][event];
    }
}

gbn_mode_state_t lookup_gbn_mode_transit(gbn_mode_session_t *gbn_mode_session, gbn_mode_event_t event)
{
    if (gbn_mode_session->cur_mode >= GBN_MODE_STATE_END || event >= GBN_MODE_EVENT_END || gbn_mode_session->cur_mode < 0 || event < 0)
    {
        log_error("[lookup_gbn_mode_transit] Invalid arguments");
        return -1;
    }

    log_info("[lookup_gbn_mode_transit] prev mode = %d", gbn_mode_session->cur_mode);
    log_debug("[lookup_gbn_mode_transit] Inputting event = %d", event);

    gbn_mode_state_t gbn_new_mode = gbn_mode_state_table[gbn_mode_session->cur_mode][event];

    log_info("[lookup_gbn_mode_transit] new mode = %d", gbn_new_mode);

    return gbn_new_mode;
}

gbn_send_state_t lookup_gbn_send_transit(gbn_send_session_t *gbn_send_session, gbn_send_event_t event)
{
    if (gbn_send_session->cur_state >= GBN_SEND_STATE_END || event >= GBN_SEND_EVENT_END || gbn_send_session->cur_state < 0 || event < 0)
    {
        log_error("[lookup_gbn_mode_transit] Invalid arguments");
        return -1;
    }

    log_info("[lookup_gbn_send_transit] prev state = %d", gbn_send_session->cur_state);
    log_debug("[lookup_gbn_send_transit] Inputting event = %d", event);

    return gbn_send_state_table[gbn_send_session->cur_state][event];
}

ssize_t sendto_host(host_session_t *host, struct gbnhdr *packet)
{
    log_debug("sending packet.type = %d, seqnum = %d", packet->type, packet->seqnum);
    int rc = sendto(host->sockfd, packet, sizeof(*packet), 0,
                    &(host->other_addr), host->other_socklen);

    if (rc < 0)
    {
        log_warn("[sendto_host] returuing rc = %d in sendto_host", rc);
    }

    return rc;
}

ssize_t recvfrom_host(host_session_t *host, struct gbnhdr *packet)
{
    int rc = maybe_recvfrom(host->sockfd, packet, sizeof(*packet), 0,
                            &(host->other_addr), &(host->other_socklen));

    if (rc < 0)
    {
        if (rc == -1 && errno == EINTR)
        {
            log_info("[recvfrom_host] maybe_recvfrom is interrupted");
        }
        else
        {
            log_error("[recvfrom_host] returuing rc = %d in maybe_recvfrom", rc);
        }
    }

    return rc;
}

gbnhdr make_pkt(uint8_t pkt_type, uint8_t seqnum, uint8_t *data, uint64_t datalen)
{
    struct gbnhdr packet;
    memset(&packet, 0, sizeof(packet));

    packet.type = pkt_type;
    packet.seqnum = seqnum;
    packet.datalen = datalen;

    if (datalen > 0)
    {
        for (int i = 0; i < datalen; i++)
        {
            packet.data[i] = data[i];
        }
    }

    uint16_t calculated_checksum = checksum(&packet, sizeof(packet));

    packet.checksum = calculated_checksum;
    log_trace("[make_pkt] appended checksum = %d", packet.checksum);

    return packet;
}

uint8_t has_seqnum(struct gbnhdr *packet, uint8_t seqnum)
{
    return packet->seqnum == seqnum;
}

int window_not_full(int base, int seqnum, int window_size)
{
    if (seqnum < base)
        seqnum += 255;
    return seqnum < base + window_size;
}

int validate_checksum(struct gbnhdr packet)
{
    uint16_t packed_checksum = packet.checksum;
    packet.checksum = 0;

    uint16_t calculated_checksum = checksum(&packet, sizeof(packet));

    if (packed_checksum == calculated_checksum)
    {
        return 0;
    }

    log_debug("[validate_checksum] checksum mismatch");
    return -1;
}

uint16_t checksum(uint8_t *buf, int nwords)
{
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{

    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB * RAND_MAX)
    {

        /*----- Receiving the packet -----*/
        int retval = recvfrom(s, buf, len, flags, from, fromlen);

        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB * RAND_MAX)
        {
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len - 1) * rand() / (RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buf[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buf[index] = c;
        }

        return retval;
    }
    /*----- Packet lost -----*/
    return (len); /* Simulate a success */
}
