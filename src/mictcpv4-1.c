#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>

#include <mictcp.h>
#include <api/mictcp_core.h>

/* The simulated loss rate given by mictcp_core */
#define LOSS_RATE 5

#define LOSS_ACCURACY 10
/* Percentage of packet loss we accept */
#define MAX_LOSS_ACCEPTANCE 1 * LOSS_ACCURACY
/* Precision */
#define WINDOW_SIZE (100 * LOSS_ACCURACY)

#define DEFAULT_TIMEOUT 50


#define ABORT_ERR(msg) do { fprintf(stderr, "%s\n", msg); exit(1); } while(0)
#define VERBOSE_ABORT_ERR(msg, exit_value) do { fprintf(stderr, "%s [%d] : %s\n", __FILE__, __LINE__, msg); exit(exit_value); } while(0)

/*****************************************************************
 * The client sends a packet with a sequence number (seqno),
 * and in the receiver server side, if the seqno of the packet
 * is different from the current server side saved seqno then
 * the packet is accepted, otherwise it means the server
 * already received this packet. The server checks this condition
 * with CHECK_SEQNO macro.
 * It then sends an ACK to the CLIENT, with the received seqno in
 * the ack_num field of the ACK packet.
 * Then the client needs to check the ACK received, through 
 * CHECK_ACKNO macro. So the ack_num needs be the same value
 * as the seqno. The CLIENT then updates the seqno through
 * UPDATE_SEQNO macro. 
 *
 * This is why we need different init values for seqno whether
 * you are CLIENT or SERVER.
 *****************************************************************/

/* MAX_SEQNO needs to be at least WINDOW_SIZE, since a modulo operation 
 * is processed to access all the elements of 
 * the loss acceptance sliding window */
#define MAX_SEQNO WINDOW_SIZE
#define INIT_CLIENT_SEQNO 0
#define INIT_SERVER_SEQNO -1

#define UPDATE_SEQNO(__seqno) ((__seqno) = ((__seqno) + 1) % MAX_SEQNO)

#define CHECK_ACKNO(__my_seqno, __their_ackno) ((__my_seqno) == (__their_ackno))
#define CHECK_SEQNO(__my_seqno, __their_seqno) ((__my_seqno) != (__their_seqno))

#define CHECK_PDU_ACKNO(__my_seqno, __pdu) CHECK_ACKNO(__my_seqno, (__pdu).header.ack_num)
#define CHECK_PDU_SEQNO(__my_seqno, __pdu) CHECK_SEQNO(__my_seqno, (__pdu).header.seq_num)

#define CONNECTION_ATTEMPTS 5

#define NEGO_PACKET_NB WINDOW_SIZE

#define ACKNO_CLEAR 0
#define NEGO_CONT -1
#define NEGO_END  -2

/* Avoid segfault errors */
#define SET_PDU_EMPTY_PAYLOAD(_pdu)         \
	do {                                \
		(_pdu).payload.data = NULL; \
		(_pdu).payload.size = 0;    \
	} while(0) 

#define SYN 1
#define ACK 1
#define FIN 1

#define NO_SYN 0
#define NO_ACK 0
#define NO_FIN 0

#define CHECK_PDU(__pdu, __syn, __ack, __fin) ((__pdu).header.syn == (__syn) && (__pdu).header.ack == (__ack) && (__pdu).header.fin == (__fin))
#define IS_PDU_SYN(pdu)     CHECK_PDU(pdu, SYN, NO_ACK, NO_FIN)
#define IS_PDU_ACK(pdu)     CHECK_PDU(pdu, NO_SYN, ACK, NO_FIN)
#define IS_PDU_FIN(pdu)     CHECK_PDU(pdu, NO_SYN, NO_ACK, FIN)
#define IS_PDU_SYN_ACK(pdu) CHECK_PDU(pdu, SYN, ACK, NO_FIN)
#define IS_PDU_FIN_ACK(pdu) CHECK_PDU(pdu, NO_SYN, ACK, FIN)

#define SET_PDU(__pdu, __syn, __ack, __fin)   \
	do {                                  \
		(__pdu).header.syn = (__syn); \
		(__pdu).header.ack = (__ack); \
		(__pdu).header.fin = (__fin); \
	} while(0) 

#define SET_PDU_SYN(pdu)     SET_PDU(pdu, SYN, NO_ACK, NO_FIN)
#define SET_PDU_ACK(pdu)     SET_PDU(pdu, NO_SYN, ACK, NO_FIN)
#define SET_PDU_FIN(pdu)     SET_PDU(pdu, NO_SYN, NO_ACK, FIN)
#define SET_PDU_SYN_ACK(pdu) SET_PDU(pdu, SYN, ACK, NO_FIN)
#define SET_PDU_FIN_ACK(pdu) SET_PDU(pdu, NO_SYN, ACK, FIN)
#define SET_PDU_CLEAR(pdu)   SET_PDU(pdu, NO_SYN, NO_ACK, NO_FIN)

#define SET_PDU_SEQNO(pdu, seqno) ((pdu).header.seq_num = (seqno))
#define SET_PDU_ACKNO(pdu, ackno) ((pdu).header.ack_num = (ackno))

#define SET_PDU_CLEAR_ACKNO(pdu)  SET_PDU_ACKNO(pdu, ACKNO_CLEAR)

/* Do we want to display information on the changing state of the socket ? */
#define DISPLAY_INFO


/* Used to get the 'global' socket, a socket which can be used by any function, whithout knowing the socket fd of the connection
 * Mainly developed since process_received_pdu cannot access socketfd, it just has access to the pdu received and the address of the sender, so it would be able to get the port which the pdu was sent to and then seek the socket which is listening to that port but we think it is much clearer to use a global socket in such situations */
#define GLOBAL_SOCKETFD (-1)
#define GLOBAL_SOCKET_INDEX 0

#define SOCKET_TABLE_SIZE 8

                       /* String to be printed */             /* Corresponding state */

const char *infos[] = {"SOCKET SUCCESSFULLY CREATED",         /* IDLE */
	               "WAITING FOR CONNECTION PROCESS",      /* WAITING_CONNECTION */
		       "SUCCESSFULLY CONNECTED",              /* CONNECTED */
		       "END OF CONNECTION PROCESS",           /* CLOSING */
		       "LOSS ACCEPTANCE NEGOCIATION PROCESS", /* NEGOCIATING */
		       "SUCCESSFULLY DISCONNECTED"            /* CLOSED */
			};

static inline void pinfo(int state)
{
	if (state < STATE_NB)
		printf("[+] %s\n", infos[state]);
}

#ifdef DISPLAY_INFO
# define SET_SOCKET_STATE(socket, _state)  \
	do {                               \
		(socket)->state = (_state);\
		pinfo(_state);             \
	} while(0)
#else
# define SET_SOCKET_STATE(socket, _state) do { (socket)->state = (_state); } while(0)
#endif

mic_tcp_sock *socket_table[SOCKET_TABLE_SIZE];
size_t available_sockets = SOCKET_TABLE_SIZE;

/* So that mic_tcp_accept is BLOCKING */
pthread_mutex_t accept_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  accept_cond  = PTHREAD_COND_INITIALIZER;

unsigned int seqno;

unsigned int loss_acceptance;

bool loss_window[WINDOW_SIZE];
int loss_nbr; 

static inline void update_loss_window(int index, bool current_packet)
{
	if (loss_window[index % WINDOW_SIZE] == true)
		loss_nbr--;

	if (current_packet)
		loss_nbr++;

	loss_window[index % WINDOW_SIZE] = current_packet;
}

static int destroy_socket(int socketfd)
{
	if (socketfd < 0 || socketfd >= SOCKET_TABLE_SIZE)
		return -1;

	if (socket_table[socketfd]) {
	
		free(socket_table[socketfd]);

		socket_table[socketfd] = NULL;

		available_sockets++;
	}

	return 0;
}

static int find_available_socket()
{
	if (available_sockets) {
		int i;

		for (i = 0; i < SOCKET_TABLE_SIZE; i++) {
			if (socket_table[i] == NULL)
				return i;
		}
	}

	return -1;
}

static mic_tcp_sock *get_active_socket(int socketfd)
{
	if (socketfd == GLOBAL_SOCKETFD)
		return socket_table[GLOBAL_SOCKET_INDEX];
	
	if (socketfd < 0 || socketfd >= SOCKET_TABLE_SIZE)
		return NULL;

	return socket_table[socketfd];
}
/* Get socket from listening port, needed by process_recv_pdu() */
/* We do not take into account potential multiple network interfaces with
 * different addresses */
static mic_tcp_sock *get_active_socket_from_port(int port)
{
	int i;

	for (i = 0; i < SOCKET_TABLE_SIZE; i++) {
		if (socket_table[i] && socket_table[i]->addr.port == port)
			return socket_table[i];
	}

	return NULL;
}

/**************************************************************************************
 *                  START OF MICTCP FUNCTIONS IMPLEMENTATION                          *
 * ***********************************************************************************/

/* Returns a socket */
int mic_tcp_socket(start_mode sm)
{
	int available_socket_index;
   	mic_tcp_sock *new;

   	printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");
   	if (initialize_components(sm) == -1) /* Mandatory call */
		   return -1;

   	set_loss_rate(LOSS_RATE);

   	/* Find available spot where to store the new socket -> If no available space for new socket */
   	if ((available_socket_index = find_available_socket()) == -1) 
		return -1;

	/* every field of the structure is 0 */   
   	if ((new = calloc(1, sizeof(*new))) == NULL)
		   ABORT_ERR("Could not calloc");

   	new->fd = available_socket_index;

	SET_SOCKET_STATE(new, IDLE);
	
   	socket_table[available_socket_index] = new;
	available_sockets--;

	if (sm == CLIENT)
		seqno = INIT_CLIENT_SEQNO;
	else
		seqno = INIT_SERVER_SEQNO;

   	return new->fd;
}

int mic_tcp_bind(int socketfd, mic_tcp_sock_addr addr)
{
   	mic_tcp_sock *s;
   	printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");

   	if ((s = get_active_socket(socketfd)) == NULL)
		return -1;
 
   	memcpy(&(s->addr), &addr, sizeof(s->addr));

   	return 0;
}

int mic_tcp_accept(int socketfd, mic_tcp_sock_addr* addr)
{
	mic_tcp_sock *s;

    	printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");

    	if ((s = get_active_socket(socketfd)) == NULL)
		return -1;

	SET_SOCKET_STATE(s, WAITING_CONNECTION);

	pthread_mutex_lock(&accept_mutex);

	while (s->state != CONNECTED)
		pthread_cond_wait(&accept_cond, &accept_mutex);

	pthread_mutex_unlock(&accept_mutex);

    	return 0;
}

int mic_tcp_connect(int socketfd, mic_tcp_sock_addr addr)
{
	mic_tcp_sock *s;
	mic_tcp_pdu connect_pdu;
	mic_tcp_pdu recv_pdu;

	int attempts = 0;
	int nb_packet;

    	printf("[MIC-TCP] Appel de la fonction: ");  printf(__FUNCTION__); printf("\n");

	if ((s = get_active_socket(socketfd)) == NULL)
		return -1;

	if (s->state == CONNECTED)
		return -1;

	memcpy(&(s->addr), &addr, sizeof(s->addr));

	/*****************************************************************************
	*				CONNECTION PROCESS
	*****************************************************************************/

	SET_PDU_EMPTY_PAYLOAD(connect_pdu);
	SET_PDU_EMPTY_PAYLOAD(recv_pdu);

	connect_pdu.header.dest_port = s->addr.port;
	
	SET_PDU_SYN(connect_pdu);

	do
	{
		IP_send(connect_pdu, addr);
	} while((IP_recv(&recv_pdu, NULL, DEFAULT_TIMEOUT) || !IS_PDU_SYN_ACK(recv_pdu)) && attempts++ < CONNECTION_ATTEMPTS);

	/* Server not responding SYN ACK to our SYN */
	if (attempts >= CONNECTION_ATTEMPTS)
		return -1;

	SET_PDU_ACK(connect_pdu);

	IP_send(connect_pdu, addr);

	/*****************************************************************************
	*				NEGOCIATING THE LOSS ACCEPTANCE PROCESS
	*****************************************************************************/

	SET_SOCKET_STATE(s, NEGOCIATING);

	SET_PDU_CLEAR(connect_pdu);

	SET_PDU_ACKNO(connect_pdu, NEGO_CONT);

	for (nb_packet = 0; nb_packet < NEGO_PACKET_NB; nb_packet++) {
		IP_send(connect_pdu, addr);
	}

	SET_PDU_ACKNO(connect_pdu, NEGO_END);
	
	do
	{
		IP_send(connect_pdu, addr);

	} while(IP_recv(&recv_pdu, NULL, DEFAULT_TIMEOUT) == -1 || recv_pdu.header.ack_num != NEGO_END);

	printf("[*] The server received %d packets out of %d sent (%d/%d lost)\n",
			recv_pdu.header.seq_num,
			NEGO_PACKET_NB,
			NEGO_PACKET_NB - recv_pdu.header.seq_num,
			NEGO_PACKET_NB);

	/* We set the right loss acceptance */
	if (NEGO_PACKET_NB - recv_pdu.header.seq_num > MAX_LOSS_ACCEPTANCE)
		loss_acceptance = MAX_LOSS_ACCEPTANCE;
	else
		loss_acceptance = NEGO_PACKET_NB - recv_pdu.header.seq_num;

	/*****************************************************************************
	*		END OF NEGOCIATING THE LOSS ACCEPTANCE PROCESS -> NOW CONNECTED
	*****************************************************************************/

	printf("[*] LOSS ACCEPTANCE %d/%d\n", loss_acceptance, NEGO_PACKET_NB);


	SET_SOCKET_STATE(s, CONNECTED);

    	return 0;
}

int mic_tcp_send (int mic_sock, char* mesg, int mesg_size)
{
	mic_tcp_sock *s;
    	mic_tcp_pdu pdu, pdurecv;

	bool retry_sending = false;
	bool accepted_loss = false;

    	printf("[MIC-TCP] Appel de la fonction: "); printf(__FUNCTION__); printf("\n");

    	if ((s = get_active_socket(mic_sock)) == NULL)
		return -1;

	if (s->state != CONNECTED)
		return -1;

	pdu.header.dest_port = s->addr.port;

	pdu.header.seq_num = seqno;

    	SET_PDU_CLEAR(pdu);

    	pdu.payload.data = mesg;
    	pdu.payload.size = mesg_size;

	SET_PDU_EMPTY_PAYLOAD(pdurecv);

    	do {
    		IP_send(pdu, s->addr);

		/* We didn't receive any ACK, 3 cases :
		 * 1) Our packet was lost
		 * 2) Their ACK was lost 
		 * 3) our timeout is too short so their ACK do not have the time to get to us */
		if (IP_recv(&pdurecv, NULL, DEFAULT_TIMEOUT) == -1) {
			/* We do not accept the loss */
			if (loss_nbr >= loss_acceptance) {
				retry_sending = true;
			}
			/* We do accept the loss */
			else {
				accepted_loss = true;

				retry_sending = false;

				printf("[*] Accepted loss\n");
			}
		}
		else if (!IS_PDU_ACK(pdurecv) || !CHECK_PDU_ACKNO(seqno, pdurecv)) {

			retry_sending = true;

		}
		/* Everything's fine, they did receive the expected packet and we received the expected ACK */
		else {

			retry_sending = false;

			accepted_loss = false;
		}


    	} while (retry_sending); 
    		
	/* We move the window so that it get rid of the first packet of the window
	 * and add the last packet we just sent */
	update_loss_window(seqno, accepted_loss);

	UPDATE_SEQNO(seqno);

    	return 0;
}

int mic_tcp_recv (int socket, char* mesg, int max_mesg_size)
{
	mic_tcp_payload payload;

	printf("[MIC-TCP] Appel de la fonction: "); printf(__FUNCTION__); printf("\n");

	payload.size = max_mesg_size;
	payload.data = mesg;

	/* app_buffer_get() is BLOCKING */
	return app_buffer_get(payload);
}

int mic_tcp_close (int socketfd)
{
	mic_tcp_pdu disconnect_pdu;
	mic_tcp_pdu recv_pdu;

	mic_tcp_sock *s;

	printf("[MIC-TCP] Appel de la fonction :  "); printf(__FUNCTION__); printf("\n");

	if ((s = get_active_socket(socketfd)) == NULL)
		return -1;

	if (s->state == IDLE)
		return -1;

	SET_SOCKET_STATE(s, CLOSING);

	/* Avoid segfault errors */
	SET_PDU_EMPTY_PAYLOAD(recv_pdu);
	SET_PDU_EMPTY_PAYLOAD(disconnect_pdu);

	disconnect_pdu.header.dest_port = s->addr.port;

	SET_PDU_FIN(disconnect_pdu);	

	do {
		IP_send(disconnect_pdu, s->addr);
	} while(IP_recv(&recv_pdu, NULL, DEFAULT_TIMEOUT) == -1 || !IS_PDU_FIN_ACK(recv_pdu));

	SET_PDU_ACK(disconnect_pdu);
	IP_send(disconnect_pdu, s->addr);

	SET_SOCKET_STATE(s, CLOSED);

	destroy_socket(socketfd);

    	return 0;
}

void process_received_PDU(mic_tcp_pdu pdu, mic_tcp_sock_addr addr)
{
	mic_tcp_pdu pdu_to_send;
	mic_tcp_sock *s;

	printf("[MIC-TCP] Appel de la fonction: "); printf(__FUNCTION__); printf("\n");

/*	if ((s = get_active_socket(GLOBAL_SOCKETFD)) == NULL) {*/
	if ((s = get_active_socket_from_port(pdu.header.dest_port)) == NULL) {
		/* Maybe we receive the FIN of the FIN-FINACK-ACK process again, so the socket is already freed and the client didn't receive our FINACK, we need to send it back */
		if (IS_PDU_FIN(pdu)) {
			SET_PDU_FIN_ACK(pdu_to_send);

			IP_send(pdu_to_send, addr);
		}

		return;
	}

	switch (s->state) {
	/***************************************************************
	 *                    WAITING_CONNECTION                       *
	 **************************************************************/
	case WAITING_CONNECTION:
		if (IS_PDU_SYN(pdu)) {

			SET_PDU_SYN_ACK(pdu_to_send);

			SET_SOCKET_STATE(s, NEGOCIATING);
		}
		break;

	/***************************************************************
	 *                          NEGOCIATING                        *
	 **************************************************************/
	/* We are waiting for connection but we already received a SYN and we already sent a SYN ACK, we 
	SET_PDU_ACK(connect_pdu);*/
	case NEGOCIATING:
		/* The client did not receive our SYN ACK */
		if (IS_PDU_SYN(pdu)) {
			SET_PDU_SYN_ACK(pdu_to_send);
		}
		/* We receive the ACK of the connection SYN - SYNACK - ACK */
		else if (IS_PDU_ACK(pdu)) {
			/* NOTHING */
		}
		/* While in negociating mode we do not want to ACK the packets we receive, so we increment the received packet number (loss_acceptance) AND WE STOP THERE, we do not send any packet back */
		else if (pdu.header.ack_num == NEGO_CONT) {
			loss_acceptance++;
			return; /* STOP THERE */
		}

		else if (pdu.header.ack_num == NEGO_END) {
			printf("[*] END of loss acceptance negociation process - Received %d packets\n", loss_acceptance);
			pdu_to_send.header.seq_num = loss_acceptance;
			pdu_to_send.header.ack_num = NEGO_END;

			SET_SOCKET_STATE(s, CONNECTED);

			/* Signal the mictcp_accept function we are now connected */	
			pthread_cond_broadcast(&accept_cond);
		}

		break;

	/***************************************************************
	 *                          CONNECTED                          *
	 **************************************************************/
	case CONNECTED:
		/* The client wants to end the connection */
		if (IS_PDU_FIN(pdu)) {

			SET_SOCKET_STATE(s, CLOSING);

			SET_PDU_FIN_ACK(pdu_to_send);

		}
		/* The client did not receive our end of negociation packet -> we send it again */
		else if (pdu.header.ack_num == NEGO_END) {
			pdu_to_send.header.seq_num = loss_acceptance;
			pdu_to_send.header.ack_num = NEGO_END;
		}
		else {

			if (CHECK_PDU_SEQNO(seqno, pdu)) {

				app_buffer_put(pdu.payload);

				seqno = pdu.header.seq_num;

			}

			pdu_to_send.header.ack_num = seqno;

			SET_PDU_ACK(pdu_to_send);
		}

		break;

	/***************************************************************
	 *                          CLOSING                            *
	 **************************************************************/
	case CLOSING:

		SET_PDU_FIN_ACK(pdu_to_send);

		SET_SOCKET_STATE(s, CLOSED);

		destroy_socket(s->fd);

		break;

	default:
		break;
	}

	SET_PDU_EMPTY_PAYLOAD(pdu_to_send);

	IP_send(pdu_to_send, addr);
}
