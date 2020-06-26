/*
tinyTLS / zeroTLS project

Copyright 2015-2020 Nesterov A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <assert.h>

// Using standart library for time. Used in client_random during 
// handshake. Scince standard does not require this to be exact we 
// can just use libc implemenetation instead of OS implementation.
#include <time.h>

#include <WinSock2.h>
#include <WS2tcpip.h>

#include "intutils.h"
#include "hash/hash.h"

#include "random.h"
#include "context.h"

#include "aes_hmac_sha.h"

#include "tls.h"

extern void PrintHex(const unsigned char *buf, unsigned int size, int shift);
extern void printASN1(int length, const uint8_t * source);

#define HOSTNAME "api.github.com"
const char sampleServer[] = HOSTNAME;
const char sampleHttp[] =
"GET /robots.txt HTTP/1.0\n"
"Host: " HOSTNAME "\n"
"User-Agent: zeroTLS\n"
//"Accept-Encoding: json\n"
"Connection: close\n"
"\n";

int ztlsLinkRecv(intptr_t socket, uint8_t * buffer, size_t size)
{
	return ::recv(socket, (char*)buffer, size, 0);
}
int ztlsLinkSend(intptr_t socket, const uint8_t * buffer, size_t size)
{
	return ::send(socket, (const char*)buffer, size, 0);
}

const int AllocSize = 3280;

int main()
{
	WSADATA wsa;
	SOCKET s;

	int r;

	SystemRandomNumberGenerator crng;
	crng.Init();

	uint8_t *memory = align((uint8_t *)malloc(AllocSize + 16), 16);

	// now try to connect to the host
	::WSAStartup(WINSOCK_VERSION, &wsa);

	s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in addr;
	addrinfo hints;
	ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
	addrinfo * lookup;
	r = ::getaddrinfo(sampleServer, NULL, &hints, &lookup);
	printf("lookup => %d\n", r);
#if 0
	auto ptr = lookup;
	for(; !!ptr; ptr = ptr->ai_next) {
		printf("Lookup res [%d, %d, %08x, %d, %s]\n", 
			ptr->ai_socktype, 
			ptr->ai_protocol,
			ptr->ai_flags,
			ptr->ai_family,
			ptr->ai_canonname);
	}
#endif
	addr.sin_family = AF_INET;
	addr.sin_port = ::htons(443);
	memcpy(&addr.sin_addr, &((sockaddr_in*)lookup->ai_addr)->sin_addr, sizeof(addr.sin_addr));

	r = ::connect(s, (const sockaddr*)&addr, sizeof(sockaddr_in));
	printf("connect => %d\n", r);

	ztlsContextImpl * ctxi = (ztlsContextImpl*)memory;
	ztlsInitContext(ctxi, AllocSize, s);

	ztlsHsState hss = { 0 };

	r = StartHandshake(ctxi, &hss, &crng, sampleServer);
	printf("StartHandshake => %d\n", r);

	do {
		r = Handshake(ctxi, &hss, sampleServer);
		printf("Handshake => %d\n", r);
	} while (r == 0);

	ctxi->Send((uint8_t*)sampleHttp, sizeof(sampleHttp) - 1); // strip \0 at the end

	printf("response:\n");
	do {
		uint8_t recvTest[128];
		r = ctxi->Receive(recvTest, 128);
		if (r < 0) {
			printf("\nres = %d\n", r);
			break;
		}
		fwrite(recvTest, 1, r, stdout);
	} while (r > 0);
	printf("\nend\n");

	printf("gracefull close : %s\n", ctxi->isClosed() ? "yes" : "no");
	ctxi->SendAlert(1, 0);

	::shutdown(s, SD_BOTH);
	::closesocket(s);

	return 0;
}
