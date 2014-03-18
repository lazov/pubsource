#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <errno.h>

// libcrypto
#include <openssl/sha.h>

// libresolv
#include <resolv.h>

#include "md5.h"
#include "session.h"

#define BLOCK_SIZE 4096
#define MAX_CHILDREN 20

#define ERROR_ACCEPT "Error accepting connection\n"
#define ERROR_FORK "Fork error\n"

const int max_listen = 3;

const unsigned int websock_port_default = 5900;

typedef void (*transfer_handler)(int, int);

struct proxy_info
{
	pthread_t thread;
	int esock, lsock;
};
static pthread_mutex_t mutex;

static struct
{
	struct sockaddr_in address;
	volatile pid_t pid;
} children[MAX_CHILDREN];
volatile static unsigned int children_count = 0;

static unsigned char buffer[BLOCK_SIZE];
static int buffer_len = 0, buffer_index = 0;

enum fail_codes
{
	Socket = 1,
	Bind,
	Listen,
	Read,
	Handshake,
	Resolve,
	Connect,
	Session,
	UnexpectedError
};

// #define fail(msg,code) (write(2, (msg), sizeof(msg) - 1), _exit(code))
void fail(const enum fail_codes code)
{
	// TODO: find some way to avoid this 35
	const char fail_msgs[][35] =
	{
		"",
		"Unable to create listening socket\n",
		"Unable to bind socket\n",
		"Unable to start listening\n",
		"Read error\n",
		"Invalid client handshake\n",
		"Unable to resolve hostname\n",
		"Cannot connect to RFB server\n",
		"Invalid session\n",
		"Unexpected error\n"
	};
	write(2, fail_msgs[code], sizeof(fail_msgs[code]) - 1);
	_exit(code);
}

static inline unsigned char sock_block(int sock, bool block)
{
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0) return 0;

	if (block) flags &= ~O_NONBLOCK;
	else flags |= O_NONBLOCK;

	if (fcntl(sock, F_SETFL, flags) < 0) return 0;

	return 1;
}

static int read_nonblock(int fd, void *buffer, size_t count)
{
	int ready;
	struct timeval timeout;

	fd_set fds;
	FD_ZERO(&fds);

	do
	{
		FD_SET(fd, &fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 500000;
		ready = select(fd + 1, &fds, NULL, NULL, &timeout);
		if (ready < 0) return 0;
	} while (!ready);

	return read(fd, buffer, count);
}

static inline size_t b64_enclen(size_t len)
{
	return (len + 2 - (len + 2) % 3) / 3 * 4;
}

static unsigned char readbytes(int fd, unsigned char encdata[], size_t length)
{
	size_t total = buffer_len - buffer_index;
	if (total < length)
	{
		memcpy(encdata, buffer + buffer_index, total);
		int pos = total;
		length -= total;

		buffer_len = 0;

		while (buffer_len < length)
		{
			total = read(fd, buffer + buffer_len, BLOCK_SIZE - buffer_len);
			if (total <= 0) return 0;
			buffer_len += total;
		}

		memcpy(encdata + pos, buffer, length);
		buffer_index = length;
	}
	else
	{
		memcpy(encdata, buffer + buffer_index, length);
		buffer_index += length;
	}

	return 1;
}

static inline int writeall(int fd, unsigned char buffer[], size_t length)
{
	int start = 0, written;
	while (start < length)
	{
		written = write(fd, buffer + start, length - start);
		if (written < 0) return written;
		if (!written) return -1;
		start += written;
	}
	return 0;
}

static void transfer_direct(int websock, int rfbsock)
{
	// TODO: handle the errors better
	// TODO: think about handling singals from dying children (it may cause problem with select())

	// Send the data in the buffer
	if (buffer_len > buffer_index)
		if (writeall(rfbsock, buffer + buffer_index, buffer_len - buffer_index) < 0)
			return;

	int ready;
	struct timeval timeout;
	fd_set fds;
	FD_ZERO(&fds);

	while (1)
	{
		FD_SET(websock, &fds);
		FD_SET(rfbsock, &fds);

		timeout = (struct timeval){.tv_sec = 1, .tv_usec = 500000};
		ready = select(websock + 1, &fds, NULL, NULL, &timeout);
		if (!ready) continue;
		if (ready < 0) return;

		// Check whether the WebSocket client has written something
		if (FD_ISSET(websock, &fds))
		{
			buffer_len = read(websock, buffer, BLOCK_SIZE);
			if (buffer_len < 0) return;
			if (!buffer_len) return;

			// Send the data to the RFB server
			if (writeall(rfbsock, buffer, buffer_len) < 0) return;
		}

		// Check whether the VNC server has written something
		if (FD_ISSET(rfbsock, &fds))
		{
			buffer_len = read(rfbsock, buffer, BLOCK_SIZE);
			if (buffer_len < 0) return;
			if (!buffer_len) return;

			// Send the data to the WebSocket server
			if (writeall(websock, buffer, buffer_len) < 0) return;
		}
	}
}

inline void transfer_proxy_17(int websock, int rfbsock)
{
	// TODO: handle the errors better
	// TODO: think about handling singals from dying children (it may cause problem with select())

	const size_t encoded_block = b64_enclen(BLOCK_SIZE);
	unsigned char buff[4], data[BLOCK_SIZE], encdata[encoded_block + 5];
	int len;

	int ready;
	struct timeval timeout;
	fd_set fds;
	FD_ZERO(&fds);

	while (1)
	{
		FD_SET(websock, &fds);
		FD_SET(rfbsock, &fds);

		timeout = (struct timeval){.tv_sec = 1, .tv_usec = 500000};
		ready = select(websock + 1, &fds, NULL, NULL, &timeout);
		if (!ready && !buffer_len) continue;
		if (ready < 0) return;

		// Check whether the WebSocket client has written something
		if ((buffer_len - buffer_index) || FD_ISSET(websock, &fds))
		{
			if (!readbytes(websock, buff, 2)) return;

			if (!(buff[0] & 0x80)) printf("fragmented\n"); // TODO

			if (buff[0] & 0x70) printf("unsupported extension\n");

			if (!(buff[1] & 0x80)) return; // TODO: If not masked, the frame is invalid

			// Check frame type
			switch (buff[0] & 0x0f)
			{
				case 0:
					printf("continue\n");
					break;
				case 1:
					// text
					break;
				case 2:
					printf("binary frame\n");
					break;
				case 8:
					// TODO: read and display the reason for closing:
					// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-15#section-5.5.1
					write(websock, "\x88\0", 2);
					return;
				case 9:
					printf("Unsupported opcode: Ping\n");
					return;
				case 0xa:
					printf("Unsupported opcode: Pong\n");
					return;
				default:
					printf("Unsupported opcode: %d\n", buff[0] & 0x0f);
					return;
			}

			// Get length of the frame data
			int plen = buff[1] & 0x7f;
			if (plen > 125)
			{
				if (plen > 126)
				{
					printf("TODO: add support for big frames\n"); // TODO
				}
				else
				{
					if (!readbytes(websock, buff, 2)) return;
					plen = ntohs(*(short *)buff);
				}
			}

			// Read the mask
			if (!readbytes(websock, buff, 4)) return; // TODO

			// Read the data
			if (!readbytes(websock, encdata, plen)) return; // TODO

			// Unmask the data
			int i;
			for(i = 0; i < plen; ++i)
				encdata[i] ^= buff[i % 4];
			encdata[plen] = 0;

			// Decode the data
			len = b64_pton(encdata, data, BLOCK_SIZE);

			if (writeall(rfbsock, data, len) < 0) return; // TODO
		}

		// Check whether the VNC server has written something
		if (FD_ISSET(rfbsock, &fds))
	 	{
			// TODO: ? support long messages (more than BLOCK_SIZE)
			len = read(rfbsock, data, BLOCK_SIZE);
			if (len < 0) return;
			if (!len) return;

			encdata[0] = (unsigned char)0x81;

			size_t enclen = b64_enclen(len);
			int start;
			if (enclen > 125)
			{
				// if (enclen > 65535) ;

				encdata[1] = (unsigned char)0x7e;
				*(short *)(encdata + 2) = htons(enclen);
				start = 4;
			}
			else
			{
				encdata[1] = (unsigned char)enclen;
				start = 2;
			}

			b64_ntop(data, len, encdata + start, enclen + 1);

			// Send the data to the WebSocket server
			if (writeall(websock, encdata, start + enclen) < 0) return;
		}
	}
}

static inline unsigned char readbyte(int fd)
{
	if (buffer_index >= buffer_len)
	{
		buffer_index = 0;
		buffer_len = read(fd, buffer, BLOCK_SIZE);
		if (buffer_len < 0) fail(Read);
		if (!buffer_len) return 0;
	}
	return buffer[buffer_index++];
}

inline void transfer_proxy_76(int websock, int rfbsock)
{
	// TODO: handle the errors better
	// TODO: think about handling singals from dying children (it may cause problem with select())

	unsigned char type, b, data[BLOCK_SIZE], encdata[BLOCK_SIZE * 2];
	int len;

	int ready;
	struct timeval timeout;
	fd_set fds;
	FD_ZERO(&fds);

	while (1)
	{
		FD_SET(websock, &fds);
		FD_SET(rfbsock, &fds);

		timeout = (struct timeval){.tv_sec = 1, .tv_usec = 500000};
		ready = select(websock + 1, &fds, NULL, NULL, &timeout);
		if (!ready && !buffer_len) continue;
		if (ready < 0) return;

		// Check whether the WebSocket client has written something
		if ((buffer_len - buffer_index) || FD_ISSET(websock, &fds))
		{
			// Read the head of the frame
			type = readbyte(websock);
			if (!buffer_len) return;

			// TODO: disconnect implementation

			if (type & 0x80)
			{
				/*if (type == 0xff) // Close the connection if this was a disconnect frame
				{
					b = readbyte(websock);
					if (!buffer_len) return;
					if (!b) write(websock, "\xff", 2); // TODO: check if this is necessary
					else ; // TODO: invalid frame
				}
				else*/
				printf("Discarding is not supported: %d\n", type);
				return;
			}
			else
			{
				if (type)
				{
					printf("Invalid frame type: %d\n", type);
					return;
				}

				len = 0;
				while (1)
				{
					b = readbyte(websock);
					if (!buffer_len) return;
					if (b == 0xff) break;
					if (len == (BLOCK_SIZE * 2 - 1)) // WARNING: This is limitation of the implementation
					{
						printf("data too long\n");
						return;
					}
					encdata[len++] = b;
				}

				// Send the data to the VNC server
				encdata[len] = 0;
				len = b64_pton(encdata, data, BLOCK_SIZE);
				if (len < 0) return;
				if (writeall(rfbsock, data, len) < 0) return;
			}
		}

		// Check whether the VNC server has written something
		if (FD_ISSET(rfbsock, &fds))
		{
			len = read(rfbsock, data, BLOCK_SIZE);
			if (len < 0) return;
			if (!len) return;

			// Send the data to the WebSocket server
			encdata[0] = '\0';
			len = b64_ntop(data, len, encdata + 1, BLOCK_SIZE * 2 - 1);
			if (len < 0) return;
			encdata[len + 1] = '\xff';
			if (writeall(websock, encdata, len + 2) < 0) return;
		}
	}
}

static unsigned long calckey(char buffer[])
{
	unsigned long key = 0, spaces = 0;
	while (*buffer)
	{
		if (isdigit(*buffer)) key = key * 10 + *buffer - '0';
		else if (*buffer == (char)' ') ++spaces;
		++buffer;
	}
	if (key % spaces) return 0;
	return key / spaces;
}

// WARNING: invalid data may not produce error
static transfer_handler handshake(int websock, char session[])
{
	const char direct[] = "DIRECT/1\r\n", proxy[] = "HTTP/1.1\r\n";

	const int query_len = 48, method_len = 4;
	int len;

	extern int errno;

	// Read at least the query line from the socket
	fprintf(stderr, "%d: handshake0\n", getpid());
	while ((buffer_len - buffer_index) < query_len)
	{
		len = read_nonblock(websock, buffer + buffer_len, BLOCK_SIZE - buffer_len);
		fprintf(stderr, "%d: read: len=%d buffer_len=%d buffer_index=%d errno=%d\n", getpid(), len, buffer_len, buffer_index, errno);
		if (len == 0) return 0;
		if (len < 0) return 0;
		buffer_len += len;
	}
	fprintf(stderr, "%d: handshake1\n", getpid());

	if (strncmp(buffer + buffer_index, "GET /", method_len + 1)) return 0;
	buffer_index += method_len + 1;

	// Copy the session information
	memcpy(session, buffer + buffer_index, session_len);
	session[session_len] = 0;
	buffer_index += session_len + 1;

	// Check whether the connection is direct
	if (strncmp(buffer + buffer_index, direct, sizeof(direct) - 1))
	{
		if (strncmp(buffer + buffer_index, proxy, sizeof(proxy) - 1)) return 0;
		buffer_index += sizeof(proxy) - 1;
	}
	else
	{
		buffer_index += sizeof(direct) - 1;
		return &transfer_direct;
	}

	// Copy the data that will be needed to the beginning of the buffer
	len = 0;
	while (buffer_index < buffer_len) buffer[len++] = buffer[buffer_index++];
	buffer_index = 0;
	buffer_len = len;

	char *origin = 0, *host = 0;

	char *key_accept = 0;
	unsigned long key1, key2;

	// Read the rest of the handshake
	int value_index = 0;
	while (1)
	{
		fprintf(stderr, "%d: handshake2\n", getpid());
		if (buffer_index == buffer_len)
		{
			len = read_nonblock(websock, buffer + buffer_len, BLOCK_SIZE - buffer_len);
			if (len == 0) return 0;
			if (len < 0) return 0;
			buffer_len += len;
		}
		fprintf(stderr, "%d: handshake3\n", getpid());

		if (value_index)
		{
			// If this is the end of the line
			if ((buffer[buffer_index - 1] == '\r') && (buffer[buffer_index] == '\n'))
			{
				buffer[buffer_index - 1] = 0;

				if (!strcmp(buffer, "host"))
				{
					host = malloc(sizeof(char) * (buffer_index - 1 - value_index));
					if (!host) _exit(1);
					strcpy(host, buffer + value_index);
				}
				else if (!strcmp(buffer, "origin") || !strcmp(buffer, "sec-websocket-origin"))
				{
					origin = malloc(sizeof(char) * (buffer_index - 1 - value_index));
					if (!origin) _exit(1);
					strcpy(origin, buffer + value_index);
				}
				else if (!strcmp(buffer, "sec-websocket-protocol"))
				{
					// TODO: finish this
					//printf("protocol: %s\n", buffer + value_index);
				}
				else if (!strcmp(buffer, "sec-websocket-key"))
				{
					// Trim the key
					while (buffer[value_index] == (char)' ')
						++value_index;
					int end = value_index;
					while (buffer[end] && (buffer[end] != (char)' '))
						++end;
					buffer[end] = 0;

					// Generate SHA-1 hash
					{
						const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
						char *key = malloc(sizeof(char) * (len + sizeof(guid) - 1));
						if (!key) _exit(1);

						len = end - value_index;
						memcpy(key, buffer + value_index, len);
						memcpy(key + len, guid, sizeof(guid) - 1);

						unsigned char hash[SHA_DIGEST_LENGTH + 1];
						SHA1(key, len + sizeof(guid) - 1, hash);
						free(key);
						const size_t enclen = b64_enclen(SHA_DIGEST_LENGTH);
						key_accept = malloc(sizeof(char) * (enclen + 1));
						if (!key_accept) _exit(1);
						b64_ntop(hash, SHA_DIGEST_LENGTH, key_accept, enclen);
						key_accept[enclen] = 0;
					}
				}
				else if (!strcmp(buffer, "sec-websocket-key1")) {key1 = calckey(buffer + value_index);}
				else if (!strcmp(buffer, "sec-websocket-key2")) {key2 = calckey(buffer + value_index);}

				++buffer_index;

				// Copy the data that will be needed to the beginning of the buffer
				len = 0;
				while (buffer_index < buffer_len) buffer[len++] = buffer[buffer_index++];
				buffer_index = value_index = 0;
				buffer_len = len;
			}
			else ++buffer_index;
		}
		else
		{
			if (buffer[buffer_index] == ':') // Check for key terminating symbol
			{
				buffer[buffer_index] = 0;
				value_index = buffer_index += 2;
			}
			else
			{
				buffer[buffer_index] = tolower(buffer[buffer_index]);

				++buffer_index;

				// Check if there are no more fields
				if ((buffer_index == 2) && (buffer[0] == (char)'\r') && (buffer[1] == (char)'\n'))
				{
					// Copy the data that will be needed to the beginning of the buffer
					len = 0;
					while (buffer_index < buffer_len) buffer[len++] = buffer[buffer_index++];
					buffer_index = 0;
					buffer_len = len;

					// Check if all the necessary information is sent
					// TODO: finish this
					if (!host) return 0;
					if (!origin) return 0;

					break;
				}
			}
		}
	}

	char *response;
	transfer_handler handler;

	fprintf(stderr, "%d: handshake6\n", getpid());
	if (key_accept)
	{
		const char *server_handshake =
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n"
			"Sec-WebSocket-Protocol: base64\r\n"
			"\r\n"
		;
		len = asprintf(&response, server_handshake, key_accept);
		free(key_accept);

		handler = &transfer_proxy_17;
	}
	else
	{
		const int key3_len = 8;

		uint32_t in[16];
		unsigned char *item;
		unsigned char hash[17];

		// Generate the information necessary for the server handshake
		// WARNING: This works only on little endian platforms
		in[0] = htonl(key1);
		in[1] = htonl(key2);
		for(item = (unsigned char *)(in + 2); buffer_index < key3_len; item++, buffer_index++)
			*item = buffer[buffer_index];
		md5((uint32_t *)hash, in);
		hash[16] = 0;

		const char *server_handshake =
			"HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
			"Upgrade: WebSocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Origin: %s\r\n"
			"Sec-WebSocket-Location: ws://%s/%s\r\n"
			"Sec-WebSocket-Protocol: base64\r\n"
			"\r\n%s"
		;

		// TODO: maybe i should get only the hostname from host

		len = asprintf(&response, server_handshake, origin, host, session, hash);

		handler = &transfer_proxy_76;
	}
	fprintf(stderr, "%d: handshake7\n", getpid());

	if (len < 0) return 0;
	fprintf(stderr, "%d: handshake8\n", getpid());
	if (writeall(websock, response, len) < 0) return 0;
	fprintf(stderr, "%d: handshake9\n", getpid());
	free(response);

	return handler;
}

void child_handler(int signum, siginfo_t *info, void *text)
{
	#define showerr(msg) write(2, "SIG: " msg "\n", sizeof(msg) + 5);

	showerr("waitpid");

	//fprintf(stderr, "%d: waitpid: %d\n", getpid(), info->si_pid);
	waitpid(info->si_pid, 0, 0);
	//fprintf(stderr, "%d: Remove child: %d\n", getpid(), info->si_pid);

	showerr("remove child");

	unsigned i;
	while (1) // Loop here because another thread may change the data
	{
		for(i = 0; i < children_count; ++i)
		{
			//printf("i=%d children[i].pid=%d\n", i, children[i].pid);
			showerr("loop");
			if (info->si_pid == children[i].pid)
			{
				children[i].pid = 0;
				//fprintf(stderr, "%d: Ready: %d\n", getpid(), info->si_pid);
				showerr("end");
				return;
			}
		}
	}
}

void *main_proxy(void *arg)
{
	struct proxy_info *pi = arg;
	unsigned i;
	char session[session_len + 1];
	struct sockaddr_in address, other;
 	int rfbsock;

	fprintf(stderr, "%d: Lock\n", getpid());
	pthread_mutex_lock(&mutex);

	// Remove dead children from the list
	for(i = 0; i < children_count; ++i)
		if (!children[i].pid)
			children[i--] = children[--children_count];

	// Cancel if no more children are allowed
	if (children_count == MAX_CHILDREN)
	{
		fprintf(stderr, "%d: Children limit exceeded\n", getpid());
		goto abort;
	}

	// Get the address of the VNC server
	fprintf(stderr, "%d: Starting handshake\n", getpid());
	sock_block(pi->esock, false);
	transfer_handler handler = handshake(pi->esock, session);
	sock_block(pi->esock, true);
	if (!handler)
	{
		fprintf(stderr, "%d: Handshake error\n", getpid());
		goto cancel;
	}
	fprintf(stderr, "%d: Handshake finished\n", getpid());
	if (!vnc_address(session, &children[children_count].address))
	{
		fprintf(stderr, "%d: Invalid session\n", getpid());
		goto cancel;
	}

	// Stop the process connected to the same RFB server (if any)
	address = children[children_count].address;
	for(i = 0; i < children_count; ++i)
	{
		other = children[i].address;
		if ((address.sin_addr.s_addr == other.sin_addr.s_addr) && (address.sin_port == other.sin_port))
		{
			fprintf(stderr, "%d: Killing %d\n", getpid(), children[i].pid);
			kill(children[i].pid, SIGTERM);
			break;
		}
	}

	fprintf(stderr, "%d: Forking...\n", getpid());

	// Create child process to handle the connection
	if (children[children_count].pid = fork()) // If this is the parent process
	{
		if (children[children_count].pid < 0) write(2, ERROR_FORK, sizeof(ERROR_FORK) - 1);
		else ++children_count;

		goto cancel;
	}
	else
	{
		close(pi->lsock);

		// Connect to the RFB server
		rfbsock = socket(PF_INET, SOCK_STREAM, 0);
		if ((rfbsock < 0) || (connect(rfbsock, (struct sockaddr *)&address, sizeof(address)) < 0)) fail(Connect);

		(*handler)(pi->esock, rfbsock);

		close(rfbsock);
		goto finish;
	}

cancel:

	buffer_index = 0;
	buffer_len = 0;

abort:

	pthread_mutex_unlock(&mutex);
	fprintf(stderr, "%d: Unlock\n", getpid());

finish:

	close(pi->esock);
	free(pi);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc > 2)
	{
		printf("Usage: wsproxy [port]\n");
		return 0;
	}

	// Daemonize
	{
		int temp = fork();
		if (temp < 0)
		{
			fprintf(stderr, "fork() failed\n");
			return 0;
		}
		if (temp) return 0;

		setsid();

		umask(0022);

		chdir("/");

		close(0);
		close(1);
		close(2);

		/*
		temp = getdtablesize();
		while (temp) close(--temp);
		*/

		open("/dev/null", O_RDONLY);
		open("/dev/null", O_WRONLY);
		dup(1);
	}

	int websock_port;
	if (argc > 1) websock_port = strtol(argv[1], 0, 10);
	else websock_port = websock_port_default;

	struct sockaddr_in address;
	int lsock, esock;

	// Create listening socket
	lsock = socket(PF_INET, SOCK_STREAM, 0);
	if (lsock < 0) fail(Socket);

	int optval = 1;
	if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
		fail(Bind);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(websock_port);
	if (bind(lsock, (struct sockaddr *)&address, sizeof(address)) < 0) fail(Bind);
	if (listen(lsock, max_listen) < 0) fail(Listen);

	// Handle dying children
	struct sigaction action = {
		.sa_sigaction = &child_handler,
		.sa_mask = 0,
		.sa_flags = (SA_SIGINFO | SA_NOCLDSTOP)
	};
	if (sigaction(SIGCHLD, &action, 0) < 0) 
	{
		fprintf(stderr, "sigaction failed\n");
		return 1;
	}

	struct proxy_info *pi;
	pthread_mutex_init(&mutex, 0);

	// Wait for clients to connect
	while (1)
	{
		// Establish a connection with a client
		if ((esock = accept(lsock, NULL, NULL)) < 0)
		{
			write(2, ERROR_ACCEPT, sizeof(ERROR_ACCEPT) - 1);
			continue;
		}

		pi = malloc(sizeof(struct proxy_info));
		if (!pi) fail(9);
		pi->esock = esock;
		pi->lsock = lsock;

		pthread_create(&pi->thread, 0, &main_proxy, pi);
		pthread_detach(pi->thread);
	}

	// pthread_mutex_destroy(&mutex);
}

// TODO: client should not reconnect automatically when the connection was closed
