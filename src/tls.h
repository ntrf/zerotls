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

#ifndef TINYTLS_TLS_H_
#define TINYTLS_TLS_H_

#include <stdint.h>

enum
{
	HEAD_CCS = 20,
	HEAD_ALERT = 21,
	HEAD_HANDSHAKE = 22,
	HEAD_APP = 23
};

namespace HandshakeType
{
	enum
	{
		hello_request = 0,
		client_hello = 1,
		server_hello = 2,
		certificate = 11,
		server_key_exchange = 12,
		certificate_request = 13,
		server_hello_done = 14,
		certificate_verify = 15,
		client_key_exchange = 16,
		finished = 20
	};
};

namespace AlertType
{
	enum
	{
		close_notify = 0,
		unexpected_message = 10,
		bad_record_mac = 20,
		record_overflow = 22,
		decompression_failure = 30,
		handshake_failure = 40,
		bad_certificate = 42,
		unsupported_certificate = 43,
		certificate_revoked = 44,
		certificate_expired = 45,
		certificate_unknown = 46,
		illegal_parameter = 47,
		unknown_ca = 48,
		access_denied = 49,
		decode_error = 50,
		decrypt_error = 51,
		protocol_version = 70,
		insufficient_security = 71,
		internal_error = 80,
		user_canceled = 90,
		no_renegotiation = 100,
	};
}


#pragma pack(push, 1)
struct TlsHead
{
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint16_t length;
};
#pragma pack(pop)

namespace StateFlags
{
	enum
	{
		Flag_Closed = 1 << 0,

		Flag_ExpectingCCS = 1 << 2,

		Flag_KeyReady = 1 << 3,
		Flag_HandshakeComplete = 1 << 4
	};
}

enum
{
	HANDSHAKE_STARTED = 1 << 0,
	HANDSHAKE_HELLO = 1 << 1,
	HANDSHAKE_SERVER_CERT = 1 << 2,
	HANDSHAKE_SERVER_KEY = 1 << 3,
	HANDSHAKE_CERT_REQUEST = 1 << 4,
	HANDSHAKE_SERVER_DONE = 1 << 5,
	HANDSHAKE_SERVER_KEX = 1 << 6,
	HANDSHAKE_CLIENT_FINISHED = 1 << 8,
	HANDSHAKE_SERVER_FINISHED = 1 << 9,

	HANDSHAKE_RESUMED = 1 << 12,
};

extern int ztlsLinkRecv(intptr_t socket, uint8_t * buffer, size_t size);
extern int ztlsLinkSend(intptr_t socket, const uint8_t * buffer, size_t size);

struct ztlsContextImpl : ztlsContext
{
	size_t limit;

	intptr_t socket;

	uint16_t recvBufferOffset;
	uint16_t sendBufferOffset;

	// new construction
	uint16_t recvSize;
	uint16_t recvOffset;

	TlsHead recvHead;
	uint8_t recvHeadSize = 0;

	uint16_t fragReceived = 0;

	uint8_t flags = 0;
	uint8_t crypto = 0;

	static const int scratchMargin = 0x20;
	static const int fragOffset = 0x20;
	static const int sendBufferSize = 512;
	static const int sendBufferExpanded = fragOffset + sendBufferSize;

	inline struct CipherState * Ciphers(size_t off) const
	{
		return (struct CipherState*)(align((void*)(this + 1), 16) + off);
	}

	// This should go into some kind of "Traits" class
	inline uint8_t * RecvBuffer() const
	{
		return (uint8_t *)this + recvBufferOffset;
	}
	inline uint8_t * RecvLimit() const
	{
		return (uint8_t*)this + sendBufferOffset;
	}

	inline uint8_t * SendBuffer() const
	{
		return (uint8_t*)this + sendBufferOffset;
	}
	inline uint8_t * SendLimit() const
	{
		return (uint8_t*)this + limit;
	}

	inline bool isReady() const 
	{  
		return !!(flags & StateFlags::Flag_HandshakeComplete);
	}

	inline bool isClosed() const
	{
		return !!(flags & StateFlags::Flag_Closed);
	}

	inline uint8_t * CalcSendBuffer(size_t data) { return align(SendLimit() - scratchMargin - data, 16); }
	
	size_t SetupSendBuffer(size_t data);
	size_t SetupEncryption(size_t stateSize);

	int RecvHeader();
	int RecvFragment(uint8_t * dest);
	int Receive(uint8_t * buffer, size_t size);

	int Send(const uint8_t * buffer, size_t size, uint8_t type = HEAD_APP);

	int SendAlertPlain(int level, int code);
	int SendAlert(int kind, int code);

	int ReceiveHandshake();
	int ReceiveHandshakeMessage(struct ztlsHsState * hs);

	void ConsumeHandshakeMessage(ztlsHsState * hs, size_t next);
};

struct ztlsHsState
{
	uint32_t HsLength; // includes header
	uint16_t HsOffset;
	uint8_t HsType;

	uint16_t state;

	int HsError;

	uint32_t slicesFullSize;

	SHA256_State finishHash;

	uint8_t prfKey[32];
	uint8_t random[64];

	uint8_t masterKey[48];

	// used by certificate storage
	union
	{
		struct
		{
			uint16_t offset;
			uint16_t count;
		} certList;

		struct
		{
			uint16_t offset;
			uint16_t length;
			uint8_t type;
		} publicKey;
	};
};

#endif