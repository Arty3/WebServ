#pragma once

#include <string>

#include "http/HttpRequest.hpp"
#include "http/HttpResponse.hpp"
#include "utils/utils.hpp"

#include "configuration/ServerConfiguration.hpp"

class RequestManager
{
public:
	/**
	* @brief Constructor that initializes the RequestManager with server configuration
	*
	* @param server_configuration Pointer to configuration containing server settings
	*/
	explicit RequestManager(const ServerConfiguration* server_configuration);

	/**
	* @brief Handles GET requests by sending back files or directory listings
	*
	* - Decodes the URL and finds the matching route
	* - Checks if URL needs redirecting
	* - Handles CGI scripts if needed
	* - Shows directory listing or file content
	* - Returns error pages if something goes wrong
	*
	* @param url The URL from the request
	* @param request The full HTTP request
	* @param http_response Where to put the response
	* @param server_listening_port Which port received the request
	*/
	void handle_http_get_request(
		const std::string&	url,
		const HttpRequest&	request,
		HttpResponse&		http_response,
		int					server_listening_port) const;

	/**
	* @brief Handles POST requests by saving uploaded files or form data
	*
	* - Checks if the request isn't too big (max 10MB)
	* - Makes sure POST is allowed for this URL
	* - Saves content to a file in the upload folder
	* - Handles both regular POST data and file uploads
	* - Returns a success or error page
	*
	* @param url The URL from the request
	* @param http_request The full HTTP request
	* @param http_response Where to put the response
	* @param server_listening_port Which port received the request
	*/
	void handle_http_post_request(
		const std::string&	url,
		const HttpRequest&	http_request,
		HttpResponse&		http_response,
		int					server_listening_port) const;

	/**
	* @brief Handles DELETE requests by removing files from the server
	*
	* - Checks if DELETE is allowed for this URL
	* - Gets the filename from the URL
	* - Makes sure the file exists
	* - Tries to delete the file
	* - Returns success or error message
	*
	* @param url The URL with the file to delete
	* @param http_response Where to put the response
	* @param server_listening_port Which port received the request
	*/
	void handle_http_delete_request(
		const std::string&	url,
		HttpResponse&		http_response,
		int					server_listening_port) const;

	/**
	* @brief Handles directory access based on route configuration
	*
	* Processing order:
	* 1. If directory listing enabled:
	*    - Creates directory if doesn't exist
	*    - Checks for configured index file
	*    - Checks for default index.html
	*    - Returns directory listing if no index found
	* 2. If directory listing disabled:
	*    - Checks for configured index file
	*    - Checks for default index.html
	*    - Returns 403 if no index found
	*
	* @param url_route Route configuration for this URL
	* @param directory_path Path to the directory
	* @param url Original URL for directory listing
	* @param http_response Response object to update on errors
	* @return Path to index file if found, empty string if handled internally
	*/
	std::string handle_directory_listing(
		const Route*		url_route,
		const std::string&	directory_path,
		const std::string&	url,
		HttpResponse&		http_response) const;

private:
	const ServerConfiguration* configuration;

	/**
	* @brief Converts URL to a full filesystem path and checks for path traversal
	*
	* - Removes query parameters (everything after '?')
	* - Combines root directory with cleaned URL
	* - Prevents directory traversal attacks by checking for '..'
	*
	* @param url The URL to resolve
	* @return Full filesystem path
	* @throws std::runtime_error If path traversal attempt detected
	*/
	[[nodiscard]]
	std::string resolve_url_path(const std::string& url) const;

	/**
	* @brief Reads entire file content into string
	*
	* Uses Utils to read file contents
	*
	* @param file_path Path to file to read
	* @return String containing file contents
	*/
	[[nodiscard]] __attribute__((always_inline))
	std::string get_file_content(const std::string& file_path) const
	{
		return Utils::read_file(file_path);
	}

	/**
	* @brief Creates an HTML page displaying directory contents
	*
	* Main steps:
	* - Creates HTML header with directory URL
	* - Opens directory (creates it if doesn't exist)
	* - For each entry in directory (except '.' and '..'):
	*   - Gets file/directory stats (size, modification time)
	*   - Adds '/' to directory names for display
	*   - Shows '-' for directory sizes
	*   - Formats file sizes in bytes
	*   - Adds entry to HTML table with name, size, and time
	* - Adds HTML footer
	*
	* @param directory_path Path to list contents of
	* @param url URL being accessed (for links)
	* @return HTML string of directory listing
	* @throws std::runtime_error If directory can't be opened or created
	*/
	[[nodiscard]]
	std::string get_directory_listing(
		const std::string& directory_path,
		const std::string& url) const;

	/**
	* @brief Determines HTTP content type based on file extension
	*
	* Supports common file types:
	* - HTML (.html, .htm)
	* - CSS (.css)
	* - Images (.jpg, .jpeg, .gif)
	* - Documents (.pdf, .txt)
	* Returns 'application/octet-stream' for unknown types
	*
	* @param file_path Path to get extension from
	* @return MIME type string
	*/
	[[nodiscard]]
	std::string get_http_request_content_type(const std::string& file_path) const;

	/**
	* @brief Checks if given path is a directory
	*
	* Uses stat() to get file information and S_ISDIR to check if it's a directory
	*
	* @param directory_path Path to check
	* @return true if path is a directory, false if not or if check fails
	*/
	[[nodiscard]]
	bool is_directory(const std::string& directory_path) const;

	/**
	* @brief Checks if a file exists at the given path
	*
	* Uses stat() to verify file existence
	*
	* @param file_path Path to check
	* @return true if file exists, false otherwise
	*/
	[[nodiscard]]
	bool file_exists(const std::string& file_path) const;

	/**
	* @brief Decodes URL-encoded strings
	*
	* - Converts %XX sequences to their ASCII characters
	* - Converts '+' to spaces
	* - Keeps other characters unchanged
	*
	* @param encoded The URL-encoded string
	* @return Decoded string
	*/
	[[nodiscard]]
	std::string url_decode(const std::string& encoded) const;

	/**
	* @brief Removes boundary markers from a form request body to get the actual content
	*
	* - Checks if the boundary exists in the body
	* - Goes through the body line by line
	* - Finds the content between boundary markers
	* - Gets rid of extra boundary text
	*
	* @param http_request_body The form data sent in the request
	* @param http_request_boundary The text that separates different parts of the form
	* @return The cleaned content without boundary markers
	*/
	[[nodiscard]]
	std::string remove_http_request_boundary(
		const std::string& http_request_body,
		const std::string& http_request_boundary) const;

	/**
	* @brief Shows an error page to the user
	*
	* - First tries to show a custom error page from the config
	* - If no custom page exists, shows a basic error message
	* - If anything goes wrong, shows a 500 server error
	*
	* @param http_response The response to put the error page in
	* @param http_status_code Which error code to show (like 404, 500)
	*/
	void serve_error_page(HttpResponse& http_response, HttpStatusCode http_status_code) const;

	/**
	* @brief Checks if a request needs CGI handling and runs the CGI script
	*
	* - Checks if it's a valid CGI request
	* - Gets the file extension (like .php)
	* - Runs the matching CGI handler if one exists
	* - Returns true if CGI was handled (success or fail)
	*
	* @param route The route config for this request
	* @param path The path to the potential CGI script
	* @param request The incoming HTTP request
	* @param response Where to put the CGI response
	* @return true if CGI was handled, false if not a CGI request
	*/
	bool handle_cgi_request(
		const Route*		route,
		const std::string&	path,
		const HttpRequest&	request,
		HttpResponse&		response) const;
};
