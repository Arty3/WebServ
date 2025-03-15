#pragma once

#include <map>
#include <string>
#include <memory>
#include <sstream>
#include <unordered_map>

#include "http/HttpMethod.hpp"

class HttpRequest
{
public:
	/**
	 * @brief Constructs a new HttpRequest object with default initialization.
	 *
	 * Initializes all member variables to their default states:
	 * - Sets HTTP request method to UNKNOWN
	 * - Marks request as incomplete
	 * - Clears all string and container members
	 * - Resets multipart and header status flags
	 *
	 * @note This constructor prepares the HttpRequest object for parsing a new HTTP request.
	 */
	HttpRequest();

	/**
	* @brief Processes an incoming HTTP request, parsing and assembling its components.
	*
	* This method handles the incremental parsing of HTTP requests, which can arrive in multiple chunks.
	* It manages different types of requests (GET, POST, multipart) and checks for complete request assembly.
	*
	* The method does several key things:
	* - Initializes a file descriptor manager if not already created
	* - Accumulates incoming request data
	* - Parses request headers when they are complete
	* - Handles different request types (multipart, content-length)
	* - Determines when a complete request has been received
	*
	* @param data The incoming chunk of HTTP request data
	* @return bool Indicates whether the request is fully parsed and complete
	*/
	bool process_incoming_http_request(const std::string& data);

	/**
	* @brief Retrieves the HTTP request method.
	*
	* @return HttpMethod The method used in the HTTP request
	*/
	[[nodiscard]] __attribute__((always_inline))
	HttpMethod get_http_request_method() const noexcept
	{
		return http_request_method;
	}

	/**
	* @brief Retrieves the URL of the HTTP request.
	*
	* @return const std::string& The requested URL
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_http_request_url() const noexcept
	{
		return http_request_url;
	}

	/**
	* @brief Retrieves the HTTP protocol version.
	*
	* @return const std::string& The HTTP version used in the request
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_http_request_version() const noexcept
	{
		return http_request_version;
	}

	/**
	 * @brief Retrieves the value of a specific HTTP request header.
	 *
	 * Searches for the header in a case-insensitive manner. If the header is not found,
	 * returns an empty string.
	 *
	 * @param key The name of the header to retrieve
	 * @return std::string The value of the header, or an empty string if not found
	 */
	[[nodiscard]]
	std::string get_http_request_header(const std::string& key) const;

	/**
	 * @brief Retrieves all HTTP request headers.
	 *
	 * @return const std::map<std::string, std::string>& A map of header keys and values
	 */
	[[nodiscard]] __attribute__((always_inline))
	const std::map<std::string, std::string>& get_http_request_headers() const
	{
		return http_request_headers;
	}

	/**
	* @brief Retrieves the body of the HTTP request.
	*
	* @return const std::string& The request body content
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_http_request_body() const noexcept
	{
		return http_request_body;
	}

	/**
	* @brief Retrieves the boundary marker for multipart requests.
	*
	* @return const std::string& The boundary string used in multipart form data
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_http_request_boundary() const noexcept
	{
		return http_request_boundary;
	}

	/**
	* @brief Checks if the HTTP request is fully parsed and complete.
	*
	* @return bool True if the request is complete, false otherwise
	*/
	[[nodiscard]] bool is_http_request_complete_check() const noexcept
	{
		return is_http_request_complete;
	}

	/**
	* @brief Checks if the HTTP request is a multipart form data request.
	*
	* @return bool True if the request is multipart, false otherwise
	*/
	[[nodiscard]] bool is_multipart() const noexcept
	{
		return is_http_request_multipart;
	}

	/**
	 * @brief Determines whether a specific header is present in the HTTP request.
	 *
	 * Performs a case-insensitive search for the given header key.
	 *
	 * @param key The header to look for in the request
	 * @return bool Indicates the presence of the header
	 */
	[[nodiscard]] bool has_http_request_header(const std::string& key) const;

private:
	HttpMethod	http_request_method;

	std::string	http_request_url;
	std::string	http_request_version;
	std::string	http_request_body;
	std::string	raw_http_request_data;
	std::string	http_request_boundary;

	bool		is_http_request_complete;
	bool		are_http_headers_complete;
	bool		is_http_request_multipart;
	size_t		http_request_body_start_index;

	std::map<std::string, std::string> http_request_headers;

	/**
	* @brief Parses the first line of an HTTP request to extract its method, URL, and version.
	*
	* This method breaks down the initial request line, which typically looks like:
	* "GET /path/to/resource HTTP/1.1"
	*
	* It does several important tasks:
	* - Extracts the HTTP method (GET, POST, DELETE)
	* - Captures the request URL
	* - Validates the HTTP protocol version
	*
	* Throws an exception if the request line is malformed or uses an unsupported HTTP version.
	*
	* @param line The first line of the HTTP request
	* @throws std::runtime_error If the request line is invalid or uses an unsupported HTTP version
	*/
	void parse_http_request_line(const std::string& line);

	/**
	* @brief Parses the headers of an HTTP request from a stream.
	*
	* This method processes each line of HTTP headers, extracting key-value pairs.
	* It performs several important tasks:
	* - Removes carriage return characters
	* - Skips empty lines
	* - Splits each header line into a key and value
	* - Trims whitespace from the header value
	* - Converts header keys to lowercase for case-insensitive matching
	* - Stores the headers in an internal map
	*
	* @param http_request_stream A stream containing the HTTP request headers
	*/
	void parse_http_request_headers(std::istringstream& http_request_stream);

	/**
	 * @brief Looks for the boundary marker in a multipart request's Content-Type header.
	 *
	 * When sending files through a web form, requests can be "multipart" which means they contain multiple pieces of data.
	 * This method checks if the Content-Type header includes a special "boundary" text that helps separate these different pieces.
	 *
	 * If it finds the boundary, the method saves this marker and indicates that the request contains multiple parts.
	 * This is useful for correctly processing forms that upload files or send complex data.
	 *
	 * @param http_request_content_type The header that might contain the boundary information
	 */
	void parse_http_request_multipart_header(const std::string& http_request_content_type);
};
