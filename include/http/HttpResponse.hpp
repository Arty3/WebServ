#pragma once

#include <map>
#include <string>

#include "http/HttpStatusCode.hpp"

class HttpResponse
{
public:
	/**
	* @brief Creates a new HTTP response with default settings
	*
	* - Sets HTTP version to 1.1
	* - Sets status code to 200 OK
	* - Adds basic response headers
	*/
	HttpResponse();

	/**
	* @brief Creates a new HTTP response with a specific status code
	*
	* - Sets HTTP version to 1.1
	* - Sets the given status code
	* - Adds basic response headers
	*
	* @param http_status_code The HTTP status code to use
	*/
	explicit HttpResponse(HttpStatusCode http_status_code);

	/**
	* @brief Changes the response status code
	*
	* @param status The new status code to use
	*/
	__attribute__((always_inline))
	void set_http_response_status_code(HttpStatusCode status) noexcept
	{
		http_response_status_code = status;
	}

	/**
	* @brief Sets or updates a response header
	*
	* @param key The header name
	* @param value The header value
	*/
	__attribute__((always_inline))
	void set_http_response_header(const std::string& key, const std::string& value)
	{
		http_response_headers[key] = value;
	}

	/**
	* @brief Sets the response body and updates Content-Length for compile time literals
	*
	* @param literal The string literal to send in the response
	*/
	template<size_t N>
	__attribute__((always_inline))
	void set_http_response_body(const char (&literal)[N])
	{
		constexpr size_t length					= N - 1;
		http_response_body						= literal;
		http_response_headers["Content-Length"]	= std::to_string(length);
	}

	/**
	* @brief Sets the response body and updates Content-Length
	*
	* @param content The content to send in the response
	*/
	__attribute__((always_inline))
	void set_http_response_body(const std::string& content)
	{
		http_response_body						= content;
		http_response_headers["Content-Length"]	= std::to_string(content.length());
	}

	/**
	* @brief Sets the Content-Type header
	*
	* @param content_type The MIME type to use
	*/
	__attribute__((always_inline))
	void set_http_response_content_type(const std::string& content_type)
	{
		http_response_headers["Content-Type"] = content_type;
	}

	/**
	* @brief Removes all headers and adds back the defaults
	*/
	__attribute__((always_inline))
	void clear_http_response_headers()
	{
		http_response_headers.clear();
		add_default_http_response_headers();
	}

	/**
	* @brief Removes a specific header
	*
	* @param key The header to remove
	*/
	__attribute__((always_inline))
	void remove_http_response_header(const std::string& key)
	{
		http_response_headers.erase(key);
	}

	/**
	* @brief Sets the Content-Length header
	*
	* @param length The length value as string
	*/
	__attribute__((always_inline))
	void set_http_response_content_length(const std::string &length)
	{
		http_response_headers["Content-Length"] = length;
	}

	/**
	* @brief Creates the complete HTTP response string
	*
	* - Adds status line
	* - Adds all headers
	* - Adds empty line
	* - Adds body if present
	*
	* @return The complete response as string
	*/
	[[nodiscard]] std::string build_http_response() const;

private:
	std::map<std::string, std::string> http_response_headers;

	HttpStatusCode	http_response_status_code;
	std::string		http_response_body;
	std::string		http_version;

	/**
	* @brief Adds the basic required headers to the response
	*
	* - Adds Server name
	* - Adds current Date
	* - Adds Connection type
	*/
	void add_default_http_response_headers();
};
