#ifndef _gbn_h
#define _gbn_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include "state.h"
#include "log.h"


/*----- Error variables -----*/
extern int h_errno;
extern int errno;

/*----- Protocol parameters -----*/
#define LOSS_PROB 1e-1    	  	/* loss probability                            */
#define CORR_PROB 1e-3   		/* corruption probability                      */
#define DATALEN   1024    	/* length of the payload                       */
#define N         1024    	/* Max number of packets a single call to gbn_send can process */
#define TIMEOUT      1    	/* timeout to resend packets (1 second)        */
#define MAX_TIMEOUT_COUNT 8	/* Number of timeouts to break the connection  */
/*----- Packet types -----*/
#define SYN      0        	/* Opens a connection                          */
#define SYNACK   1        	/* Acknowledgement of the SYN packet           */
#define DATA     2        	/* Data packets                                */
#define DATAACK  3        	/* Acknowledgement of the DATA packet          */
#define FIN      4        	/* Ends a connection                           */
#define FINACK   5        	/* Acknowledgement of the FIN packet           */
#define RST      6        	/* Reset packet used to reject new connections */

#define h_addr h_addr_list[0] /* for backward compatibility */

/*----- Go-Back-n packet format -----*/
typedef struct gbnhdr
{
	uint8_t  type;            /* packet type (e.g. SYN, DATA, ACK, FIN)     */
	uint8_t  seqnum;          /* sequence number of the packet              */
    uint16_t checksum;        /* header and payload checksum                */
	uint64_t datalen;         /* length of data in packet                   */
    uint8_t data[DATALEN];    /* pointer to the payload                     */
} __attribute__((packed)) gbnhdr;

typedef enum
{
	RECEIVER = 0,
	SENDER
} host_type_t;

typedef struct
{
	host_type_t host_type;
	connection_state_t cur_state;
	int sockfd;
	struct sockaddr other_addr;
	socklen_t other_socklen;
} host_session_t;

typedef struct
{
	gbn_send_state_t cur_state;
	int window_shifted;
} gbn_send_session_t;
typedef struct
{
	gbn_mode_state_t cur_mode;
} gbn_mode_session_t;

extern host_session_t host_session;
extern gbn_send_session_t gbn_send_session;
extern gbn_mode_session_t gbn_mode_session;

void gbn_init(int sockfd);
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_listen(int sockfd, int backlog);
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_socket(int domain, int type, int protocol);
int gbn_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int gbn_close(int sockfd);
int gbn_receiver_close(int sockfd);
int gbn_sender_close(int sockfd);
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags);

#endif
