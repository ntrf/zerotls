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


#ifndef TINYTLS_CIPHERSTATE_H_
#define TINYTLS_CIPHERSTATE_H_

struct CipherState
{
};

typedef int32_t(CipherState::* WrapPacketFn)(uint8_t * output, uint8_t type, const uint8_t * data, unsigned length);
typedef int32_t(CipherState::* UnwrapPacketFn)(uint8_t * output, uint8_t type, const uint8_t * data, unsigned length);

struct CipherSuiteDefinition
{
	uint16_t size;
	WrapPacketFn wrap;
	UnwrapPacketFn unwrap;
};

#endif
