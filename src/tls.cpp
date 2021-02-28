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

#include <string.h>

#include "intutils.h"
#include "context.h"

#include "tls.h"

#include "aes_hmac_sha.h"
#include "aes128_gcm.h"

#define CIPHER AES128_GCM

const int AlertReceived = -1000;

static size_t cipherSuiteSizes[] = {
	0, // TLS_NONE
	sizeof(AES128_HMAC_SHA), // TLS_**_AES128_CBC_SHA256
	sizeof(AES128_GCM) // TLS_**_AES128_GCM_SHA256
};

static CipherSuiteDefinition cipherSuites[] = {
	{ 0, nullptr, nullptr }, // TLS_NONE
	{
		sizeof(AES128_HMAC_SHA), // TLS_**_AES128_CBC_SHA256
		(WrapPacketFn)&AES128_HMAC_SHA::WrapPacket,
		(UnwrapPacketFn)&AES128_HMAC_SHA::UnWrapPacket
	},
	{
		sizeof(AES128_GCM), // TLS_**_AES128_GCM_SHA256
		(WrapPacketFn)&AES128_GCM::WrapPacket,
		(UnwrapPacketFn)&AES128_GCM::UnWrapPacket
	}
};

int ztlsContextImpl::RecvHeader()
{
	// Make sure we receive the entire head
	if (recvHeadSize == 5)
		return 1;

	int r = ::ztlsLinkRecv(socket, (uint8_t*)&recvHead + recvHeadSize, 5 - recvHeadSize);
	if (r <= 0)
		return r;
	recvHeadSize += r;

	// we still don't have the entire head
	if (recvHeadSize < 5)
		return 0;

	if (recvHead.type < 0x14 || recvHead.type > 0x17) {
		return ZTLS_ERR_BADMSG;
	}
	if (recvHead.version_major < 3 || (recvHead.version_major == 3 && recvHead.version_minor < 3)) {
		return ZTLS_ERR_INSECURE;
	}

	// Make sure it fits
	fragReceived = 0;

	return 1;
}

int ztlsContextImpl::RecvFragment(uint8_t * dest)
{
	int r = 0;

	if (recvHeadSize < 5) {
		r = RecvHeader();
		if (r <= 0)
			return r;
	}

	uint16_t l = bswap16(recvHead.length);

	uint8_t * limit = RecvLimit();
	if (fragReceived > l)
		return ZTLS_ERR_OVERFLOW;
	if (dest + l >= limit - 0x30) {
		return ZTLS_ERR_OVERFLOW;
	}

	dest += fragReceived;

	r = ::ztlsLinkRecv(socket, dest, l - fragReceived);
	if (r <= 0)
		return r;

	fragReceived += r;
	if (fragReceived > l)
		return ZTLS_ERR_OVERFLOW;
	if (fragReceived < l)
		return 0; // We didn't get full packet yet

	// prepare for next call
	recvHeadSize = 0;
	fragReceived = 0;

	// return length of current fragment
	return l;
}

int ztlsContextImpl::Receive(uint8_t * buffer, size_t size)
{
	CIPHER * dec_context = (CIPHER *)Ciphers(sizeof(CIPHER));

	//### check context ready
	if (!isReady())
		return 0;

	int ret = 0;

	intptr_t l = 0;

	uint8_t * bdest = RecvBuffer();
	uint8_t * bsrc = bdest + fragOffset;

	for (;;) {
		if (recvSize >= size) {
			const uint8_t * in = ((uint8_t*)this + recvOffset);
			memcpy(buffer, in, size);
			recvSize -= size;
			recvOffset += size;
			ret += size;
			return ret;
		} else if (recvSize > 0) {
			const uint8_t * in = ((uint8_t*)this + recvOffset);
			memcpy(buffer, in, recvSize);
			buffer += recvSize;
			size -= recvSize;
			ret += recvSize;
			recvSize = 0;
		}
	get_packet:
		// receive another packet
		int r = RecvFragment(bsrc);

		// if we can't get anything yet, retrun whatever we've managed 
		// to copy from previous fragments
		if (r == 0)
			return ret;

		// error?
		if (r < 0) return r;

		// try to decode packet
		l = dec_context->UnWrapPacket(bdest, recvHead.type, bsrc, r);
		if (l < 0) return ZTLS_ERR_TAMPERED;

		// ignore empty packets
		if (l == 0)	goto get_packet;

		if (recvHead.type == HEAD_ALERT) {
			if (l != 2)
				return ZTLS_ERR_BADMSG;

			// connection close
			if (bdest[0] == 1 && bdest[1] == 0) {
				flags = StateFlags::Flag_Closed;
				return ret;
			}

			// kill connection on alerts
			if (bdest[0] != 1)
				return ZTLS_ERR_BADMSG;

			// ignore warning alert
			//### might not be what we want
		} else if (recvHead.type != HEAD_APP) {
			// unexpected message
			return ZTLS_ERR_BADMSG;
		}

		// prepare for data copying
		recvOffset = bdest - (uint8_t *)this;
		recvSize = l;
	}
}

// This function works as all-or-nothing
int ztlsContextImpl::Send(const uint8_t * buffer, size_t size, uint8_t type)
{
	if (!isReady())
		return 0;

	//### check for key expiring
	uint8_t * workBuf = SendBuffer();
	CIPHER * enc_context = (CIPHER*)Ciphers(0);
	int res = 0;
	do {
		uint32_t l = size > sendBufferSize ? sendBufferSize : size;

		//### check for buffer size

		uint8_t * begin = align(workBuf + 16, 16) - CIPHER::lead;
		//### check (CIPHER::lead + 5 < 16)

		int32_t pl = enc_context->WrapPacket(begin, type, buffer, l);

		// space for the header
		begin -= 5;

		TlsHead *sendHead = (TlsHead*)begin;
		sendHead->type = type;
		sendHead->version_major = 3;
		sendHead->version_minor = 3;
		sendHead->length = bswap16(pl);

		int r = ::ztlsLinkSend(socket, (const uint8_t*)begin, pl + 5);
		if (r <= 0)
			return r;

		size -= l;
		buffer += l;
	} while (size > 0);

	return 1;
}

int ztlsContextImpl::SendAlertPlain(int level, int code)
{
	// This might destroy something, but most of the time such alerts are fatal anyway
	//### check limits
	uint8_t * data = SendBuffer();
	data[0] = HEAD_ALERT;
	data[1] = 3;
	data[2] = 3;
	data[3] = 0;
	data[4] = 2;
	data[5] = level;
	data[6] = code;

	return ::ztlsLinkSend(socket, (const uint8_t*)data, 7);
}

int ztlsContextImpl::SendAlert(int level, int code)
{
	uint8_t data[2];
	data[0] = level;
	data[1] = code;
	return Send(data, 2, HEAD_ALERT);
}

int ztlsContextImpl::ReceiveHandshakeMessage(ztlsHsState * hs)
{
	//### Check for unsent app data

	int l;

	CIPHER * dec_context = nullptr;
	if (crypto > 0)
		dec_context = (CIPHER *)Ciphers(sizeof(CIPHER));

	uint8_t * bdest;

	goto check_size;

	// Receive header (and probably more than that)
	while (true) {
		//### aligned offset & copy
		bdest = RecvBuffer() + hs->HsOffset + recvSize;
		if (!crypto) {
			l = RecvFragment(bdest);
			if (l <= 0)
				return l;
		} else {
			int r;
			uint8_t * bsrc = bdest + fragOffset;
		get_packet:
			r = RecvFragment(bsrc);
			if (r <= 0)
				return r;

			// try to decode packet
			l = dec_context->UnWrapPacket(bdest, recvHead.type, bsrc, r);
			if (l < 0) return ZTLS_ERR_TAMPERED;

			// ignore empty packets
			if (l == 0)	goto get_packet;
		}

		// check for CCS we're waiting for
		if (recvHead.type == HEAD_CCS) {
			if (l != 1 || bdest[0] != 1)
				return ZTLS_ERR_BADMSG;
			if (!(flags & StateFlags::Flag_ExpectingCCS))
				return ZTLS_ERR_TAMPERED;
			flags &= ~StateFlags::Flag_ExpectingCCS;
			return 1;
		} else if (recvHead.type == HEAD_ALERT) {
			if (l != 2)
				return ZTLS_ERR_BADMSG;

			// handshake will handle them
			return 1;
		} else if (recvHead.type != HEAD_HANDSHAKE) {
			return ZTLS_ERR_BADMSG;
		}

		recvSize += l;

	check_size:
		// parse the header if we can
		if (hs->HsLength == 0) {
			if (recvSize < 4)
				continue;

			uint8_t * data = RecvBuffer() + hs->HsOffset;

			uintptr_t type = data[0];
			size_t length = (data[1] << 16) | (data[2] << 8) + data[3];

			// handle "certificate" message
			if (type == HandshakeType::certificate) {
				if (length < 6)
					return ZTLS_ERR_BAD_CERTIFICATE;
				hs->HsLength = 4 + 6;
				// indicate that this is the first packet
				hs->slicesFullSize = 0;
			} else {
				hs->HsLength = 4 + length;
			}
			hs->HsType = type;

			//### check bounds
		}

		// check if got the entire message
		if (recvSize >= hs->HsLength) {
			recvOffset = (RecvBuffer() - (uint8_t *)this) + hs->HsOffset;
			return recvSize;
		}
	}
}

void ztlsContextImpl::ConsumeHandshakeMessage(ztlsHsState * hs, size_t next)
{
	recvSize -= hs->HsLength;
	recvOffset += hs->HsLength;
	uint8_t * to = RecvBuffer() + hs->HsOffset;
	if (recvSize > 0) {
		memmove(to, (uint8_t *)this + recvOffset, recvSize);
		recvOffset = to - (uint8_t *)this;
	}

	// read next slice
	hs->HsLength = next;
}

size_t ztlsContextImpl::SetupSendBuffer(size_t data)
{
	size_t slice = CalcSendBuffer(data) - (uint8_t *)this;

	sendBufferOffset = slice;

	return slice;
}
size_t ztlsContextImpl::SetupEncryption(size_t stateSize)
{
	uint8_t * postEncContext = (uint8_t*)Ciphers(stateSize * 2);
	recvBufferOffset = align(postEncContext + ztlsContextImpl::scratchMargin, 16) - (uint8_t*)this;

	return recvBufferOffset;
}

void ztlsInitContext(void * memory, size_t size, intptr_t socket)
{
	ztlsContextImpl * ctx = (ztlsContextImpl *)memory;

	memset(ctx, 0, sizeof(*ctx));

	ctx->limit = size;
	ctx->socket = socket;

	// no space wasted on crypto
	ctx->SetupEncryption(sizeof(size_t));
}
