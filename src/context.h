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


#ifndef CONTEXT_H_
#define CONTEXT_H_

#ifndef PROGMEM
#define PROGMEM
#endif

#include "hash/hash.h"

enum ztlsError
{
	/// zeroTLS has completed this operation.
	ZTLS_COMPLETE = 1,

	/// zeroTLS did not receive enough data to continue. You will have to
	/// retry later.
	ZTLS_NONE = 0,

	/// Negotiated parameters can't be used for secure communication. Server 
	/// reconfiguration is required.
	ZTLS_ERR_INSECURE = -11501,

	/// Negotiated parameters are not supported by tinyTLS and communication 
	/// could not be continued.
	ZTLS_ERR_UNSUPPORTED = -11502,

	/// Connection between peers is most likely affected by a third-praty. 
	/// tinyTLS will break the connection to ensure security. Note: This
	/// error code should never be reported if both sides of the link are 
	/// standard-compliant.
	ZTLS_ERR_TAMPERED = -11503,

	/// Unexpected message format received. Could be possible in case of a
	/// connection error or malicios actions from third-party.
	ZTLS_ERR_BADMSG = -11504,

	/// Ran out of memory
	ZTLS_ERR_OVERFLOW = -11505,

	/// Server certificate was invalid
	ZTLS_ERR_BAD_CERTIFICATE = -11506,

	/// Server did not allow us access w/o a client certificate
	ZTLS_ERR_ACCESS_DENIED = -11507
};

struct ztlsSessionInfo
{
	uint8_t sessionIdLength;
	uint8_t sesionId[64];
	uint8_t masterKey[48];
};

struct ztlsContext {};

inline uint8_t *align(void *p, size_t by)
{
	return (uint8_t *)(((intptr_t)p + by - 1) & ~(by - 1));
}

void ztlsInitContext(void * memory, size_t size, intptr_t socket);

int StartHandshake(struct ztlsContextImpl *ctx, struct ztlsHsState *hs, class SystemRandomNumberGenerator * crng, const char *sni);
int Handshake(ztlsContextImpl * ctx, ztlsHsState * hs, const char * sni);

extern void PrfGenBlock_v1_2(
	uint8_t * output, size_t outLen, 
	const uint8_t * secret, size_t sectretLen, 
	const char * label, const uint8_t * seed, size_t seedLen);

#endif