#pragma once

#include <cstdint>

/* int8 for better portability */
enum class HttpMethod : int8_t
{
	UNKNOWN,
	GET,
	POST,
	DELETE
};
