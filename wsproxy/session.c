#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <libmemcached/memcached.h> // libmemcached

#include "session.h"

#include <stdio.h>

int vnc_address(char session[], struct sockaddr_in *address)
{
	const char *memcache_host = "192.168.192.195";
	const unsigned int memcache_port = 11211;

	memcached_st *memc = memcached_create(NULL);
	if (!memc) return 0;
	memcached_return_t rc;
	//printf("%s\n", memcached_strerror(memc, rc));

	// Initialize server list
	memcached_server_st *servers = memcached_server_list_append(NULL, memcache_host, memcache_port, &rc);
	if (!servers) return 0;
	memcached_server_push(memc, servers);
	memcached_server_free(servers);

	// Initialize keys for the query
	const size_t key_len = session_len + 6;
	char key_host[key_len], key_port[key_len];
	strncpy(key_host, session, session_len);
	strcpy(key_host + session_len, "_host");
	strncpy(key_port, session, session_len);
	strcpy(key_port + session_len, "_port");
	char *keys[2] = {key_host, key_port};
	size_t keys_len[2] = {key_len - 1, key_len - 1};

	char return_key[MEMCACHED_MAX_KEY], *return_value;
	size_t return_key_len, return_value_len;

	memcached_mget(memc, (const char *const *)keys, keys_len, 2);

	int set = 0;

	uint32_t flags;
	while (1)
	{
		return_key_len = MEMCACHED_MAX_KEY;
		return_value = memcached_fetch(memc, return_key, &return_key_len, &return_value_len, &flags, &rc);
		if (!return_value) break;

		if (!strncmp(key_host, return_key, return_key_len))
		{
			struct hostent *info = gethostbyname(return_value);
			if (!info) return 0;
			address->sin_addr = *(struct in_addr *)*info->h_addr_list;

			set |= 0x1;
		}
		else if (!strncmp(key_port, return_key, return_key_len))
		{
			address->sin_port = htons(strtol(return_value, 0, 10));

			set |= 0x2;
		}
		free(return_value);
	}

	memcached_free(memc);

	if (set == 0x3)
	{
		address->sin_family = AF_INET;
		return 1;
	}
	else return 0;
}
