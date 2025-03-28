#pragma once

#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <unordered_set>

#include "configuration/Route.hpp"

/*
	Linux stack allocates 8MB, so this is safe,
	disregarding the max post request size.

	These can all be modified in the config.
*/

#define _MAX_REQUEST_BODY_SIZE		1048576		/* 1MB */
#define _MAX_POST_REQUEST_SIZE		10485760	/* 10MB */
#define _MAX_REQUEST_READ_SIZE		65536		/* 64KB */
#define _DEFAULT_REQUEST_READ_SIZE	4096		/* 1 page */

class ServerConfiguration
{
public:
	/**
	 * @brief Constructs a new ServerConfiguration object with default settings.
	 *
	 * Initializes the maximum client request body size to 1MB and sets the current URL route to null.
	 */
	ServerConfiguration();

	/**
	 * @brief Retrieves the list of server listening ports.
	 *
	 * @return std::unordered_set<int> An unordered_set containing the configured listening port numbers
	 */
	[[nodiscard]] __attribute__((always_inline))
	std::unordered_set<int> get_server_listening_ports() const noexcept
	{
		return server_listening_ports;
	}

	/**
	 * @brief Retrieves the server names and their associated root directories.
	 *
	 * @return const std::map<std::string, std::string>& A map of server names to root directories
	 */
	[[nodiscard]] __attribute__((always_inline))
	const std::map<std::string, std::string>& get_server_names() const noexcept
	{
		return server_names;
	}

	/**
	 * @brief Retrieves the path to the default error page.
	 *
	 * @return const std::string& The file path of the default error page
	 */
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_default_error_page_path() const noexcept
	{
		return default_error_page_path;
	}

	/**
	 * @brief Gets the maximum allowed size for a post request.
	 *
	 * @return size_t The maximum request size in bytes
	 */
	[[nodiscard]] __attribute__((always_inline))
	size_t get_max_post_request_size() const noexcept
	{
		return max_post_request_size;
	}

	/**
	 * @brief Gets the maximum allowed size for a client request body.
	 *
	 * @return size_t The maximum request body size in bytes
	 */
	[[nodiscard]] __attribute__((always_inline))
	size_t get_max_request_body_size() const noexcept
	{
		return max_request_body_size;
	}

	/**
	 * @brief Gets the socket read request size
	 *
	 * @return size_t The reading buffer size
	 */
	[[nodiscard]] __attribute__((always_inline))
	size_t get_request_read_size() const noexcept
	{
		return request_read_size;
	}

	/**
	 * @brief Retrieves the root directory for the server configuration.
	 *
	 * @return const std::string& The root directory path
	 */
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_root_directory() const noexcept
	{
		return root_directory;
	}

	/**
	 * @brief Retrieves the currently active URL route being configured.
	 *
	 * @return Route* Pointer to the current URL route, or nullptr if no route is being configured
	 */
	[[nodiscard]] __attribute__((always_inline))
	Route* get_current_url_route() const noexcept
	{
		return current_url_route;
	}

	/**
	 * @brief Retrieves all configured URL routes.
	 *
	 * @return const std::vector<Route>& An unordered_set of all configured routes
	 */
	[[nodiscard]] __attribute__((always_inline))
	const std::vector<Route>& get_url_routes() const noexcept
	{
		return url_routes;
	}

	/**
	 * @brief Finds the most specific URL route for a given listening port and file path.
	 *
	 * This method searches through all configured routes to find the most precise match.
	 * It helps determine which route should handle a specific incoming request by:
	 * - First checking if the route belongs to the correct listening port
	 * - Then verifying if the route matches the requested file path
	 * - Finally selecting the route with the longest (most specific) matching URL path
	 *
	 * For example, if you have routes "/", "/users", and "/users/profile", and a request
	 * comes for "/users/profile/settings", it will choose the "/users/profile" route.
	 *
	 * @param listening_port The server port number to match
	 * @param file_path The requested URL path
	 * @return const Route* A pointer to the most specific matching route, or nullptr if no match is found
	 */
	[[nodiscard]]
	const Route* find_url_route_for_listening_port(
		int listening_port, const std::string& file_path) const;

	/**
	 * @brief Adds a new listening port to the server configuration.
	 *
	 * Validates that the port number is positive. Throws an exception if the port is invalid.
	 *
	 * @param new_server_listening_port The port number to add
	 * @throws std::runtime_error If the port number is zero
	 */
	inline void add_server_listening_port(unsigned new_server_listening_port) noexcept(false)
	{
		if (!new_server_listening_port)
			throw std::runtime_error(
				"Port cannot be negative or zero"
			);

		auto ret = server_listening_ports.emplace(
			static_cast<int>(new_server_listening_port)
		);

		if (!ret.second)
			throw std::runtime_error(
				"Port is duplicate"
			);
	}

	/**
	 * @brief Associates a server name with a root directory.
	 *
	 * @param name The server name
	 * @param root The root directory for this server name
	 */
	__attribute__((always_inline))
	void add_server_name(const std::string& name, const std::string& root)
	{
		server_names[name] = root;
	}

	/**
	 * @brief Sets the path for the default error page.
	 *
	 * @param file_path The file path to the default error page
	 */
	__attribute__((always_inline))
	void set_default_error_page_path(const std::string& file_path) noexcept
	{
		default_error_page_path = file_path;
	}

	/**
	 * @brief Sets the maximum size allowed for a client post request.
	 *
	 * @param size The maximum request size in bytes
	 */
	__attribute__((always_inline))
	void set_max_post_request_size(size_t size) noexcept
	{
		max_post_request_size = size;
	}

	/**
	 * @brief Sets the maximum size allowed for a client request body.
	 *
	 * @param size The maximum request body size in bytes
	 */
	__attribute__((always_inline))
	void set_max_request_body_size(size_t size) noexcept
	{
		max_request_body_size = size;
	}

	/**
	 * @brief Sets the http request socket read size
	 *
	 * @param size The request reading size
	 */
	__attribute__((always_inline))
	void set_request_read_size(size_t size) noexcept
	{
		request_read_size = size;
	}

	/**
	 * @brief Sets the root directory for the server configuration.
	 *
	 * @param file_path The root directory path
	 */
	__attribute__((always_inline))
	void set_root_directory(const std::string& file_path) noexcept
	{
		root_directory = file_path;
	}

	/**
	 * @brief Starts a new URL route configuration.
	 *
	 * Creates a new route, sets its filesystem root and listening port,
	 * and makes it the current route being configured.
	 *
	 * @param file_path The path for the new route
	 * @param port The listening port for this route (optional)
	 */
	void start_url_route(const std::string& file_path, int port = 0);

	/**
	 * @brief Ends the current URL route configuration.
	 *
	 * Sets the current route pointer to null, indicating no route is being configured.
	 */
	__attribute__((always_inline))
	void end_url_route() noexcept
	{
		current_url_route = nullptr;
	}

	/**
	* @brief Checks if the server configuration is valid and complete.
	*
	* Validates the server configuration by ensuring:
	* - At least one listening port is configured
	* - A root directory is specified
	* - At least one URL route is defined
	*
	* @return bool True if the configuration is valid, false otherwise
	*/
	[[nodiscard]] inline
	bool is_valid() const noexcept
	{
		if (server_listening_ports.empty() || root_directory.empty())
			return false;

		if (url_routes.empty())
			return false;

		return true;
	}

	/**
	 * @brief Generates a detailed string representation of the server configuration.
	 *
	 * Creates a human-readable report of the server's configuration, including:
	 * - Listening ports
	 * - Server name
	 * - Root directory
	 * - Maximum client body size
	 * - Default error page path
	 * - Detailed route configurations
	 *    - URL paths
	 * - Route-specific settings like:
	 *    - Filesystem roots
	 *    - Directory listing status
	 *    - Index files
	 *    - Allowed HTTP methods
	 *    - Upload directories
	 *    - Redirection rules
	 *
	 * Useful for debugging, logging, or displaying server setup information.
	 *
	 * @return std::string A formatted configuration overview
	 */
	[[nodiscard]]
	std::string get_server_configuration_string() const;

private:
	size_t max_request_body_size	= _MAX_REQUEST_BODY_SIZE;
	size_t max_post_request_size	= _MAX_POST_REQUEST_SIZE;
	size_t request_read_size		= _DEFAULT_REQUEST_READ_SIZE;

	std::unordered_set<int>				server_listening_ports;
	std::vector<Route>					url_routes;
	std::map<std::string, std::string>	server_names;

	Route*		current_url_route;
	std::string	default_error_page_path;
	std::string	root_directory;
};
