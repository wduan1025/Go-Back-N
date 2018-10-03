#include <unistd.h>
#include "helper.h"
#include "state.h"
#include "gbn.h"
#include "handler.h"

host_session_t host_session;
gbn_mode_session_t gbn_mode_session;
gbn_send_session_t gbn_send_session;
uint8_t fin_pkt_seqnum = -1;
int gbn_base = 1;
int gbn_next_seqnum = 1;
uint8_t gbn_expected_seqnum = 1;

void gbn_init(int sockfd)
{
	log_set_quiet(1);
	log_set_level(LOG_DEBUG);

	host_session.sockfd = sockfd;
	host_session.cur_state = CLOSED;

	gbn_send_session.cur_state = MAKE_AND_SEND;
	gbn_send_session.window_shifted = 0;

	gbn_mode_session.cur_mode = SLOW;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags)
{
	int window_size = 1 << gbn_mode_session.cur_mode; // gbn_mode = 0, 1, 2

	// create packet window for window_size 1,2,4
	struct gbnhdr send_pkt_4[1 << FAST];
	struct gbnhdr send_pkt_2[1 << MODERATE];
	struct gbnhdr send_pkt_1[1 << SLOW];

	struct gbnhdr *send_q[3] = {send_pkt_1, send_pkt_2, send_pkt_4};
	// create packet for receiving from receiver
	struct gbnhdr receive_pkt;
	memset(&receive_pkt, 0, sizeof(receive_pkt));

	// chunk_start is the starting index of a the chunk in buf that is going to be
	// sent to receiver.
	int chunk_start = 0;

	// loop until chunk_start >= len(buf ends) and gbn_base == gbn_next_seqnum(window ends)
	while (chunk_start < len || (gbn_base < gbn_next_seqnum))
	{
		window_size = 1 << gbn_mode_session.cur_mode; // gbn_mode = 0, 1, 2
		signal(SIGALRM, timeout_wait_dataack_handler);
		alarm(TIMEOUT);
		// at state INPROGRESS, append new packet to the end of window and send them.
		if (gbn_send_session.cur_state == MAKE_AND_SEND)
		{
			log_info("[gbn_sender] ******************* [start] INPROGRESS *******************");
			/* send */
			while (window_not_full(gbn_base, gbn_next_seqnum, window_size) && chunk_start < len)
			{
				/* Get data from input buf*/
				uint8_t data[DATALEN];
				int data_len;
				for (data_len = 0; data_len < DATALEN && chunk_start + data_len < len; data_len++)
				{
					data[data_len] = *((char *)buf + chunk_start + data_len);
				}
				chunk_start += DATALEN;

				// send_pkt_i is a cycler array, so need to modulo window_size
				// window_pos = 0, 1, 2, 3
				int window_pos = (gbn_next_seqnum - 1) % window_size;
				struct gbnhdr new_packet = make_pkt(DATA, gbn_next_seqnum, data, data_len);
				memcpy(send_q[gbn_mode_session.cur_mode] + window_pos, &new_packet, sizeof(new_packet));
				log_debug("[gbn_send] packet %d sent", (*(send_q[gbn_mode_session.cur_mode] + window_pos)).seqnum);
				while (sendto_host(&host_session, send_q[gbn_mode_session.cur_mode] + window_pos) < 0)
				{
					log_error("[gbn_send] packet send failure");
				}
				// increment next_seq. seqnum is uint_8_t so it overflows to 1 when reaches 256
				gbn_next_seqnum = gbn_next_seqnum % 255 + 1;
			}
			log_debug("window status: ########################################## ");
			for (int i = 0; i < window_size; i++)
			{
				log_debug("%d", (*(send_q[gbn_mode_session.cur_mode] + i)).seqnum);
			}
			log_debug("gbn_base = %d, gbn_next_seqnum = %d ##############################", gbn_base, gbn_next_seqnum);
			// when loop ends normally, window is filled and it's time to wait for ACKs
			gbn_send_session.cur_state = ACKNOWLEDGE;
			log_info("[gbn_send] window full or file ended");
		}

		/* receive */
		/* timer restarts right after receiving one packet */
		/* and if there is room for new packet, it is sent immediately */
		if (gbn_send_session.cur_state == ACKNOWLEDGE)
		{
			gbn_send_session.window_shifted = 0;
			gbn_mode_state_t prev_mode = gbn_mode_session.cur_mode;

			while (gbn_base != gbn_next_seqnum && gbn_send_session.cur_state == ACKNOWLEDGE)
			{
				log_info("[gbn_sender] ******************* [start] ACKKNOLEDGE *******************");
				int recv_rc = recvfrom_host(&host_session, &receive_pkt);

				if (recv_rc < 0 || validate_checksum(receive_pkt) < 0)
				{
					log_error("[gbn_send] received corrupted packet or returned from timeout handler");
					continue;
				}

				if (validate_checksum(receive_pkt) != -1 && receive_pkt.type == DATAACK)
				{
					int acked_seqnum = receive_pkt.seqnum;
					log_debug("[gbn_send] ack for %d received", acked_seqnum);
					// if gbn_base shifts, new packets will be sent right after timeout, so go to INPROGRESS
					// check acked_seqnum > gbn_base

					if ((receive_pkt.seqnum - gbn_base) % 256 < window_size)
					{
						log_debug("[gbn_send] gbn_base %d upgraded to %d", gbn_base, acked_seqnum + 1);
						gbn_send_session.window_shifted = 1;
						gbn_base = receive_pkt.seqnum % 255 + 1;
					}

					log_debug("[gbn_send] gbn_base is %d, gbn_next_seqnum is %d", gbn_base, gbn_next_seqnum);
					signal(SIGALRM, timeout_wait_dataack_handler);
					alarm(TIMEOUT);
					log_debug("dfsjfkjdfk");
				}
			}

			log_debug("gbn_send_session.cur_state = %d", gbn_send_session.cur_state);
			log_debug("gbn_send_session.window_shifted = %d", gbn_send_session.window_shifted);

			// if return because gbn_base hits gbn_next_seqnum, should ACCELERATE.
			if (gbn_base == gbn_next_seqnum)
			{
				gbn_mode_session.cur_mode = lookup_gbn_mode_transit(&gbn_mode_session, ACCELERATE);
			}
			else
			{
				gbn_mode_session.cur_mode = lookup_gbn_mode_transit(&gbn_mode_session, DECELERATE);

				if (prev_mode > gbn_mode_session.cur_mode)
				{
					chunk_start -= ((gbn_next_seqnum - gbn_base + 255) % 255) * DATALEN;
					gbn_next_seqnum = gbn_base;
				}
			}

			if (gbn_send_session.window_shifted || prev_mode > gbn_mode_session.cur_mode)
			{
				gbn_send_session.cur_state = lookup_gbn_send_transit(&gbn_send_session, BASE_SHIFTED);
			}
		}

		log_debug("Current gbn_send_session.cur_state = %d", gbn_send_session.cur_state);

		// no useful ACK received during ACKNOWLEDGE, resend all packets in window
		if (gbn_send_session.cur_state == RESEND)
		{
			log_info("[gbn_sender] ******************* [start] TIMEOUT RESEND *******************");
			// iterating in a cycling array
			int counter = 0;
			int window_pos = (gbn_base - 1) % window_size;

			while (counter < window_size)
			{
				log_debug("[gbn_send] packet %d sent", (*(send_q[gbn_mode_session.cur_mode] + window_pos)).seqnum);

				while (sendto_host(&host_session, send_q[gbn_mode_session.cur_mode] + window_pos) < 0)
				{
					log_error("[gbn_send] packet send failure");
				}

				window_pos = (window_pos + 1) % window_size;
				counter++;
			}

			gbn_send_session.cur_state = lookup_gbn_send_transit(&gbn_send_session, RESEND_CUR_WIN);
		}
	}

	alarm(0);
	return sizeof(gbnhdr);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags)
{
	// make packet for later use
	struct gbnhdr send_pkt;
	struct gbnhdr receive_pkt;

	memset(&send_pkt, 0, sizeof(send_pkt));
	memset(&receive_pkt, 0, sizeof(receive_pkt));

	send_pkt = make_pkt(DATAACK, gbn_expected_seqnum - 1, NULL, 0);
	log_info("[gbn_recv] ******************* [start] receiving DATA gbn_expected_seqnum = %d *******************", gbn_expected_seqnum);

	/* when receiving non-valid packets, corrupted packets, incorrect seqnum, must continue to receive */
	while (host_session.cur_state != FIN_RCVD)
	{
		int receive_rc = -1;

		/* If receiver does not receive any packets within MAX_TIMEOUT_COUNT*TIMEOUT seconds, connection is broken.
		   Receiver will self close the connection without handshake.
		*/
		signal(SIGALRM, timeout_no_pkt_handler);
		alarm(MAX_TIMEOUT_COUNT * TIMEOUT);

		receive_rc = recvfrom_host(&host_session, &receive_pkt);
		if (receive_rc < 0 || validate_checksum(receive_pkt) < 0)
		{
			log_error("[gbn_recv] lost packet or received corrupted packet, receive_rc = %d", receive_rc);
			log_debug("[gbn_recv] sending ack packet for seqnum %d", send_pkt.seqnum);

			if (sendto_host(&host_session, &send_pkt) < 0)
			{
				return -1;
			}

			continue;
		}

		/* if receive packets, reset TIMER */
		alarm(MAX_TIMEOUT_COUNT * TIMEOUT);

		if (validate_checksum(receive_pkt) != -1)
		{
			log_trace("[gbn_recv] packet not corrupted, packet.type = %d", receive_pkt.type);

			if (receive_pkt.type == DATA)
			{
				log_debug("[gbn_recv] received DATA, seqnum %d, expected seqnum %d",
						  receive_pkt.seqnum, gbn_expected_seqnum);
				if (receive_rc > 0 && has_seqnum(&receive_pkt, gbn_expected_seqnum))
				{
					// received useful DATA packet
					log_trace("[gbn_recv] received packet not corrupted && correct seqnum");
					/* extract packet*/
					char *receive_data = (char *)(receive_pkt.data);
					/* deliver packet*/
					char *buf_ptr = (char *)buf;
					for (int i = 0; i < receive_pkt.datalen; i++)
					{
						buf_ptr[i] = *receive_data;
						receive_data++;
					}
					log_debug("[gbn_recv] gbn_expected_seqnum from %d to %d",
							  gbn_expected_seqnum, gbn_expected_seqnum % 255 + 1);

					// send packet and update expected sequence number
					send_pkt = make_pkt(DATAACK, gbn_expected_seqnum, NULL, 0);
					log_debug("[gbn_recv] sending ack packet for seqnum %d", send_pkt.seqnum);
					if (sendto_host(&host_session, &send_pkt) < 0)
					{
						return -1;
					}
					gbn_expected_seqnum = gbn_expected_seqnum % 255 + 1;

					return receive_pkt.datalen;
				}
				// for every case except for the above one, an ack packet should be sent.
				else
				{
					log_debug("[gbn_recv] sending ack packet for seqnum %d", send_pkt.seqnum);
					if (sendto_host(&host_session, &send_pkt) < 0)
					{
						return -1;
					}
					log_error("[gbn_recv] received empty packet or incorrect seqnum");

					continue;
				}
			}
			else if (receive_pkt.type == FIN)
			{
				log_info("[gbn_recv] received packet.type = FIN, seqnum = %d", receive_pkt.seqnum);
				fin_pkt_seqnum = receive_pkt.seqnum;
				host_session.cur_state = lookup_connect_transit(&host_session, RCVD_FIN);

				/* return 0 to receiver to stop receiving, without sending DATAACK */
				return 0;
			}
			else
			{
				log_debug("[gbn_recv] sending ack packet for seqnum %d", send_pkt.seqnum);
				if (sendto_host(&host_session, &send_pkt) < 0)
				{
					return -1;
				}
				log_error("[gbn_recv] receive unexpected packet.type = %d", receive_pkt.type);

				continue;
			}
		}
		else
		{
			log_debug("[gbn_recv] sending ack packet for seqnum %d", send_pkt.seqnum);
			if (sendto_host(&host_session, &send_pkt) < 0)
			{
				return -1;
			}
			log_error("[gbn_recv] packet corrupted.");

			continue;
		}
	}

	log_error("[gbn_recv] Ooops! You shouldn't see this");
	return -1;
}

int gbn_close(int sockfd)
{
	switch (host_session.host_type)
	{
	case RECEIVER:
		log_info("[gbn_close] host_type = receiver");
		return gbn_receiver_close(sockfd);
	case SENDER:
		log_info("[gbn_close] host_type = sender");
		return gbn_sender_close(sockfd);
	default:
		log_error("[gbn_close] host_type = error.");
	}

	return (-1);
}

int gbn_sender_close(int sockfd)
{
	if (host_session.cur_state != ESTABLISHED)
	{
		return -1;
	}

	struct gbnhdr packet_fin;
	struct gbnhdr packet_finack;
	memset(&packet_fin, 0, sizeof(packet_fin));
	memset(&packet_finack, 0, sizeof(packet_finack));
	packet_fin = make_pkt(FIN, rand() % 100, NULL, 0);
	uint8_t expected_finack_seqnum = packet_fin.seqnum;

	/* if timeout for waiting FINACK, the state is changed to ESTABLISHED for resend FIN */
	/* after MAX_TIMEOUT_COUNT * TIMEOUT, the state is changed to BROKEN, close anyway */
	log_info("[gbn_sender_close] Entering while loop, current state ESTABLISHED(4) = %d", host_session.cur_state);
	while (host_session.cur_state != CLOSED)
	{

		log_info("[gbn_sender_close] ******************* [start] send FIN *******************");
		if (host_session.cur_state == ESTABLISHED)
		{
			log_debug("[gbn_sender_close] send FIN(4) = %d, seqnum = %d", packet_fin.type, packet_fin.seqnum);

			int send_rc = sendto_host(&host_session, &packet_fin);
			if (send_rc < 0)
			{
				return (-1);
			}

			/* start count timeout for FIN, waiting to receive FINACK */
			signal(SIGALRM, timeout_wait_finack_handler);
			alarm(TIMEOUT);

			/* change to FIN_SENT */
			host_session.cur_state = lookup_connect_transit(&host_session, SEND_FIN);
			log_info("[gbn_sender_close] Current state FIN_SENT(6): %d", host_session.cur_state);
		}

		log_info("[gbn_sender_close] ******************* [start] receive FINACK *******************");
		if (host_session.cur_state == FIN_SENT)
		{
			int receive_rc = recvfrom_host(&host_session, &packet_finack);

			if (receive_rc < 0 || validate_checksum(packet_finack) < 0)
			{
				/* if interrupted (func error / not receiving FINACK), rc = -1, we re-loop the while to re-send FIN */
				log_error("[gbn_recv] lost packet or received corrupted packet");
				continue;
			}

			if (packet_finack.type == FINACK && packet_finack.seqnum == expected_finack_seqnum)
			{
				/* cancel Time out for FINACK */
				alarm(0);
				log_debug("[gbn_sender_close] Received FINACK(5) = %d, seqnum = %d", packet_finack.type, packet_finack.seqnum);

				/* change to CLOSED */
				host_session.cur_state = lookup_connect_transit(&host_session, RCVD_FINACK);
				log_info("[gbn_sender_close] Current state CLOSED(0): %d", host_session.cur_state);
				log_info("[gbn_sender_close] The connection is going to be gracefully closed");
				break;
			}
		}

		if (host_session.cur_state == BROKEN)
		{
			log_error("[gbn_sender_close] host_session.cur_state = BROKEN");
			close(sockfd);
			return -1;
		}
	}

	return close(sockfd);
}

int gbn_receiver_close(int sockfd)
{
	if (host_session.cur_state == BROKEN)
	{
		close(sockfd);
		return -1;
	}

	/* The FIN packet has been received in gbn_recv() */

	if (host_session.cur_state != FIN_RCVD)
	{
		return (-1);
	}

	struct gbnhdr packet_fin;
	struct gbnhdr packet_finack;
	memset(&packet_fin, 0, sizeof(packet_fin));
	memset(&packet_finack, 0, sizeof(packet_finack));
	packet_finack = make_pkt(FINACK, fin_pkt_seqnum, NULL, 0);

	/* after receiver got a FIN, it will enter CLOSE_WAIT state */
	/* after MAX_TIMEOUT_COUNT * TIMEOUT in CLOSE_WAIT, the receiver will assume that the connection can be safely closed */
	signal(SIGALRM, timeout_to_close_handler);
	alarm(MAX_TIMEOUT_COUNT * TIMEOUT);

	log_info("[gbn_receiver_close] Entering while loop, current state FIN_RCVD(6) = %d", host_session.cur_state);
	while (host_session.cur_state != CLOSED)
	{
		log_info("[gbn_receiver_close] ******************* [start] send FINACK *******************");
		/* send FINACK to sender */
		if (host_session.cur_state == FIN_RCVD)
		{

			log_debug("[gbn_receiver_close] Sending FINACK(5) = %d, seqnum = %d", packet_finack.type, packet_finack.seqnum);
			int send_rc = sendto_host(&host_session, &packet_finack);
			if (send_rc < 0)
			{
				return (-1);
			}

			host_session.cur_state = lookup_connect_transit(&host_session, SEND_FINACK);
			log_info("[gbn_receiver_close] Current state CLOSE_WAIT(7): %d", host_session.cur_state);
		}

		/* during CLOSE_WAIT state, any incoming FIN pkt will be replied with a FINACK */
		log_info("[gbn_receiver_close] ******************* [start] receive additional FIN (if FINACK loss) *******************");
		if (host_session.cur_state == CLOSE_WAIT)
		{
			/* receive FIN from sender */
			int receive_rc = recvfrom_host(&host_session, &packet_fin);
			if (receive_rc < 0 || validate_checksum(packet_fin) < 0)
			{
				log_error("[gbn_receiver_close] lost packet or received corrupted packet");
				continue;
			}

			if (packet_fin.type != FIN)
			{
				continue;
			}

			/* receive a FIN pkt, make a FINACK with same seqnum, and change state to FIN_RCVD to send FINACK */
			log_debug("[gbn_receiver_close] Received FIN(4) = %d, seqnum = %d", packet_fin.type, packet_fin.seqnum);

			fin_pkt_seqnum = packet_fin.seqnum;
			packet_finack = make_pkt(FINACK, fin_pkt_seqnum, NULL, 0);

			host_session.cur_state = lookup_connect_transit(&host_session, RCVD_FIN);
			log_info("[gbn_receiver_close] Current state FIN_RCVD(6): %d", host_session.cur_state);
		}
	}

	log_info("[gbn_receiver_close] Current state CLOSED(0): %d", host_session.cur_state);

	return close(sockfd);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen)
{
	host_session.host_type = SENDER;
	host_session.other_addr = *server;
	host_session.other_socklen = socklen;

	struct gbnhdr packet_syn;
	struct gbnhdr packet_synack;
	memset(&packet_syn, 0, sizeof(packet_syn));
	memset(&packet_synack, 0, sizeof(packet_synack));

	packet_syn = make_pkt(SYN, rand() % 100, NULL, 0);
	uint8_t expected_synack_seqnum = packet_syn.seqnum;

	/* if time out, sender state will be changed to CLOSED in signal handler*/
	/* so that the while loop restarts and resend SYN */
	/* if multiple timeout (5 times), the state is changed to BROKEN */

	while (host_session.cur_state != ESTABLISHED)
	{
		log_info("[gbn_connect] Entering while loop, current state CLOSED(0) = %d", host_session.cur_state);

		log_info("[gbn_connect] ******************* [start] send SYN *******************");
		if (host_session.cur_state == CLOSED)
		{
			log_debug("[gbn_connect] send SYN(0) = %d, seqnum = %d", packet_syn.type, packet_syn.seqnum);

			int send_rc = sendto_host(&host_session, &packet_syn);
			if (send_rc < 0)
			{
				return -1;
			}

			/* start count time out for SYNACK */
			signal(SIGALRM, timeout_wait_synack_handler);
			alarm(TIMEOUT);

			/* change to SYN_SENT */
			host_session.cur_state = lookup_connect_transit(&host_session, SEND_SYN);
			log_info("[gbn_connect] Current state SYN_SENT(2): %d", host_session.cur_state);
		}

		log_info("[gbn_connect] ******************* [start] receive SYNACK *******************");
		if (host_session.cur_state == SYN_SENT)
		{
			int receive_rc = recvfrom_host(&host_session, &packet_synack);
			if (receive_rc < 0 || validate_checksum(packet_synack) < 0)
			{
				/* if interrupted, rc = -1, we re-loop the while to re-send SYN */
				log_error("[gbn_connect] lost packet or received corrupted packet");
				continue;
			}

			if (packet_synack.type == SYNACK && packet_synack.seqnum == expected_synack_seqnum)
			{
				/* cancel Time out for SYNACK */
				alarm(0);
				log_debug("[gbn_connect] Received SYNACK(1) = %d, seqnum = %d", packet_synack.type, packet_synack.seqnum);

				/* change to ESTABLISHED */
				host_session.cur_state = lookup_connect_transit(&host_session, RCVD_SYNACK);
				log_info("[gbn_connect] Current state ESTABLISHED(4): %d", host_session.cur_state);
				break;
			}
		}

		if (host_session.cur_state == BROKEN)
		{
			log_error("[gbn_connect] Connection setup failed after %d seconds", MAX_TIMEOUT_COUNT);
			return -1;
		}
	}

	log_trace("[gbn_connect] Returning gbn_connect with state ESTABLISHED(4): %d", host_session.cur_state);
	return 0;
}

int gbn_listen(int sockfd, int backlog)
{
	host_session.host_type = RECEIVER;

	if (host_session.cur_state == CLOSED && backlog == 1)
	{
		host_session.cur_state = lookup_connect_transit(&host_session, OPEN_LISTEN);
		return 0;
	}

	return -1;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen)
{
	int rc = bind(sockfd, server, socklen);
	return rc;
}

int gbn_socket(int domain, int type, int protocol)
{
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	int sockfd = socket(domain, type, protocol);
	gbn_init(sockfd);
	return sockfd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen)
{
	host_session.other_addr = *client;
	host_session.other_socklen = *socklen;

	if (host_session.cur_state != LISTEN)
	{
		return (-1);
	}

	struct gbnhdr packet_syn;
	struct gbnhdr packet_synack;
	struct gbnhdr packet_rst;
	memset(&packet_syn, 0, sizeof(packet_syn));
	memset(&packet_synack, 0, sizeof(packet_synack));
	memset(&packet_rst, 0, sizeof(packet_rst));
	packet_synack = make_pkt(SYNACK, 0, NULL, 0);
	packet_rst = make_pkt(RST, 0, NULL, 0);
	uint8_t expected_synack_seqnum = -1;

	while (host_session.cur_state != ESTABLISHED)
	{
		log_info("[gbn_accept] ******************* [start] receive SYN *******************");
		if (host_session.cur_state == LISTEN)
		{
			/* receive SYN from sender */
			int receive_rc = recvfrom_host(&host_session, &packet_syn);
			/* keep listening if packet lost or corrupt or not syn */
			if (receive_rc < 0)
			{
				sendto_host(&host_session, &packet_rst);
				continue;
			}

			if (validate_checksum(packet_syn) < 0 || packet_syn.type != SYN)
			{
				log_error("[gbn_accept] lost packet or received corrupted packet");
				continue;
			}

			log_debug("[gbn_accept] Received SYN(0) = %d, seqnum = %d", packet_syn.type, packet_syn.seqnum);

			expected_synack_seqnum = packet_syn.seqnum;
			packet_synack = make_pkt(SYNACK, expected_synack_seqnum, NULL, 0);

			host_session.cur_state = lookup_connect_transit(&host_session, RCVD_SYN);
			log_info("[gbn_accept] Current state SYN_RCVD(3): %d", host_session.cur_state);
		}

		log_info("[gbn_accept] ******************* [start] send SYNACK *******************");
		/* send SYNACK to sender */
		if (host_session.cur_state == SYN_RCVD)
		{
			log_trace("[gbn_accept] Sending SYNACK(1) = %d, seqnum = %d", packet_synack.type, packet_synack.seqnum);
			int send_rc = sendto_host(&host_session, &packet_synack);
			if (send_rc < 0)
			{
				return (-1);
			}

			host_session.cur_state = lookup_connect_transit(&host_session, SEND_SYNACK);
			log_info("[gbn_accept] Current state ESTABLISHED(4): %d", host_session.cur_state);

			break;
		}
	}

	log_trace("[gbn_accept] Returning gbn_accept with state ESTABLISHED(4): %d", host_session.cur_state);
	return sockfd;
}
