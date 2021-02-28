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

#if WIN32

#pragma comment(lib, "bcrypt.lib")
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

class SystemRandomNumberGenerator
{
public:
	int Init()
	{
		return 1;
	}

	void Shutdown()
	{
	}

	int GenerateRandomBytes(uint8_t * data, size_t length)
	{
		NTSTATUS v = ::BCryptGenRandom(NULL, data, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (BCRYPT_SUCCESS(v))
		{
			return -1;
		}
		return length;
	}
};

#elif defined(__linux__)

#include <fcntl.h>
#include <unistd.h>

class SystemRandomNumberGenerator
{
public:
	int srcfd;

	int Init()
	{
		srcfd = ::open("/dev/random", O_RDONLY);
		return 1;
	}

	void Shutdown()
	{
		::close(srcfd);
	}

	int GenerateRandomBytes(uint8_t * data, size_t length)
	{
		::read(srcfd, data, length);
		return length;
	}
};

#else

#error "No RNG implementation for this platform"

#endif