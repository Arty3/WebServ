#pragma once

#include <map>
#include <set>
#include <string>
#include <stdexcept>

#include "http/HttpMethod.hpp"

class Route
{
public:
	/**
	 * @brief Constructs a Route with default settings for a given URL path.
	 *
	 * Initializes a route with:
	 * - Specified URL path
	 * - Default root directory "./"
	 * - No redirection
	 * - Default index file "index.html"
	 * - Directory listing disabled
	 * - Default upload directory "./upload"
	 * - No specific listening port
	 * - GET method allowed by default
	 *
	 * @param file_path The URL path for this route
	 */
	explicit Route(const std::string& file_path);

	/**
	 * @brief Constructs a Route with custom upload and directory listing settings.
	 *
	 * Allows more detailed configuration of route parameters:
	 * - Specified URL path
	 * - Custom upload directory
	 * - Directory listing control
	 * - Specific server listening port
	 * - Default root directory "./"
	 * - No redirection
	 * - Default index file "index.html"
	 * - GET method allowed by default
	 *
	 * @param file_path The URL path for this route
	 * @param upload_directory Directory for file uploads
	 * @param directory_listing_enabled Flag to enable/disable directory listing
	 * @param server_listening_port The port this route is associated with
	 */
	explicit Route(
		const std::string& file_path,
		const std::string& upload_directory,
		bool directory_listing_enabled,
		int server_listening_port
	);

	/**
	 * @brief Retrieves the server listening port for this route.
	 *
	 * @return int The configured listening port number
	 */
	[[nodiscard]] __attribute__((always_inline))
	int get_server_listening_port() const noexcept
	{
		return server_listening_port;
	}

	/**
	* @brief Retrieves the URL path for this route.
	*
	* @return const std::string& The configured URL path
	*
	* Example:
	* Route route("/users");
	* std::string path = route.get_url_path(); // Returns "/users"
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_url_path() const noexcept
	{
		return url_path;
	}

	/**
	* @brief Retrieves the filesystem root directory for this route.
	*
	* @return const std::string& The base directory for file serving
	*
	* Example:
	* Route route("/files");
	* route.set_filesystem_root("/var/www/html");
	* std::string root = route.get_filesystem_root(); // Returns "/var/www/html"
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_filesystem_root() const noexcept
	{
		return file_system_root;
	}

	/**
	* @brief Retrieves the redirect URL for this route.
	*
	* @return const std::string& The URL to redirect to, if set
	*
	* Example:
	* Route route("/old-path");
	* route.set_redirect_url("/new-path");
	* std::string redirect = route.get_redirect_url(); // Returns "/new-path"
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_redirect_url() const noexcept
	{
		return redirect_url;
	}

	/**
	* @brief Retrieves the default index file for this route.
	*
	* @return const std::string& The name of the default index file
	*
	* Example:
	* Route route("/");
	* std::string index = route.get_index_file(); // Returns "index.html" (default)
	* route.set_index_file("home.html");
	* index = route.get_index_file(); // Returns "home.html"
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_index_file() const noexcept
	{
		return index_file;
	}

	/**
	* @brief Retrieves the upload directory for this route.
	*
	* @return const std::string& The directory where uploaded files are stored
	*
	* Example:
	* Route route("/upload");
	* std::string uploadDir = route.get_upload_directory(); // Returns "./upload" (default)
	* route.set_upload_directory("/var/uploads");
	* uploadDir = route.get_upload_directory(); // Returns "/var/uploads"
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string& get_upload_directory() const noexcept
	{
		return upload_directory;
	}

	/**
	* @brief Checks if directory listing is enabled for this route.
	*
	* @return bool True if directory listing is allowed, false otherwise
	*/
	[[nodiscard]] __attribute__((always_inline))
	bool is_directory_listing_enabled() const noexcept
	{
		return directory_listing;
	}

	/**
	* @brief Checks if a specific HTTP method is allowed for this route.
	*
	* The allowed methods are; GET, POST, and DELETE.
	*
	* @param http_method The HTTP method to check
	* @return bool True if the method is allowed, false otherwise
	*/
	[[nodiscard]] __attribute__((always_inline))
	bool is_http_method_allowed(HttpMethod http_method) const
	{
		return allowed_http_methods.find(http_method) != allowed_http_methods.end();
	}

	/**
	* @brief Checks if the route has a configured redirection.
	*
	* @return bool True if a redirect URL is set, false otherwise
	*/
	[[nodiscard]] __attribute__((always_inline))
	bool should_redirect() const noexcept
	{
		return !redirect_url.empty();
	}

	/**
	* @brief Sets the server listening port for this route.
	*
	* @param server_listening_port_number The port number to associate with this route
	*/
	__attribute__((always_inline))
	void set_server_listening_port(int new_server_listening_port) noexcept
	{
		server_listening_port = new_server_listening_port;
	}

	/**
	* @brief Sets the filesystem root directory for this route.
	*
	* @param directory_path The base directory for file serving
	*/
	__attribute__((always_inline))
	void set_filesystem_root(const std::string& directory_path) noexcept
	{
		file_system_root = directory_path;
	}

	/**
	* @brief Sets the redirect URL for this route.
	*
	* @param redirection_url The URL to redirect to when this route is accessed
	*/
	__attribute__((always_inline))
	void set_redirect_url(const std::string& redirection_url) noexcept
	{
		redirect_url = redirection_url;
	}

	/**
	* @brief Sets the default index file for this route.
	*
	* @param index_filename The name of the file to serve when a directory is requested
	*/
	__attribute__((always_inline))
	void set_index_file(const std::string& index_filename) noexcept
	{
		index_file = index_filename;
	}

	/**
	* @brief Enables or disables directory listing for this route.
	*
	* @param enabled Flag to turn directory listing on or off
	*/
	__attribute__((always_inline))
	void set_directory_listing(bool enabled) noexcept
	{
		directory_listing = enabled;
	}

	/**
	* @brief Sets the upload directory for this route.
	*
	* @param directory_path The directory where uploaded files will be stored
	*/
	__attribute__((always_inline))
	void set_upload_directory(const std::string& directory_path) noexcept
	{
		upload_directory = directory_path;
	}

	/**
	* @brief Adds a CGI handler for a specific file extension.
	*
	* Associates an executable with a file extension for CGI processing.
	*
	* @param extension The file extension (e.g., ".py", ".php")
	* @param executable The path to the executable that will handle the CGI script
	*/
	__attribute__((always_inline))
	void add_cgi_handler(const std::string& extension, const std::string& executable)
	{
		cgi_handlers[extension] = executable;
	}

	/**
	* @brief Checks if a CGI handler exists for a given file extension.
	*
	* @param extension The file extension to check for a CGI handler
	* @return bool True if a CGI handler exists for the extension, false otherwise
	*/
	__attribute__((always_inline))
	bool has_cgi_handler(const std::string& extension) const
	{
		return cgi_handlers.find(extension) != cgi_handlers.end();
	}

	/**
	* @brief Retrieves the CGI handler executable for a given file extension.
	*
	* @param extension The file extension to find a CGI handler for
	* @return const std::string The path to the CGI handler executable,
	*	or an empty string if no handler exists
	*/
	[[nodiscard]] __attribute__((always_inline))
	const std::string get_cgi_handler(const std::string& extension) const
	{
		const auto iterator = cgi_handlers.find(extension);

		if (iterator != cgi_handlers.end())
			return iterator->second;

		return "";
	}

	/**
	* @brief Adds an allowed HTTP method to this route.
	*
	* Only GET, POST, and DELETE methods can be added.
	*
	* @param http_method The HTTP method to allow
	*/
	__attribute__((always_inline))
	void add_allowed_http_method(HttpMethod http_method) noexcept(false)
	{
		auto ret = allowed_http_methods.emplace(http_method);

		if (!ret.second)
			throw std::runtime_error(
				"HTTP method is duplicate"
			);
	}

	/**
	* @brief Removes an HTTP method from the allowed methods for this route.
	*
	* Only GET, POST, and DELETE methods can be removed.
	*
	* @param http_method The HTTP method to disallow
	*/
	__attribute__((always_inline))
	void remove_allowed_http_method(HttpMethod http_method)
	{
		allowed_http_methods.erase(http_method);
	}

	/**
	* @brief Determines if a requested URL path corresponds to this route.
	*
	* Handles complex URL matching rules:
	* - Removes query parameters from the path
	* - Supports exact path matches
	* - Allows matching child paths under route paths
	* - Ensures proper path boundary handling
	*
	* @param requested_path The full URL path to be evaluated
	* @return bool True if the path matches the route's configuration, false otherwise
	*/
	[[nodiscard]]
	bool does_http_request_matches_a_url_route(const std::string& requested_path) const;

	/**
	* @brief Compares two Route objects
	*
	* @param other the other operand Route object
	* @return bool True if they have the same url_path
	*/
	bool operator==(const Route& other) const noexcept
	{
		return this->url_path == other.url_path;
	}

private:
	std::string	url_path;
	std::string	file_system_root;
	std::string	redirect_url;
	std::string	index_file;
	std::string	upload_directory;
	bool		directory_listing;
	int			server_listening_port;

	std::set<HttpMethod>				allowed_http_methods;
	std::map<std::string, std::string>	cgi_handlers;

	/**
	* @brief Converts a URL path to a filesystem path.
	*
	* Translates a web URL into a corresponding file system location
	* based on the route's configuration.
	*
	* @param requested_url The URL path to convert
	* @return std::string The mapped filesystem path
	*/
	[[nodiscard]]
	std::string map_url_to_filesystem_path(const std::string& requested_url) const;
};

/* Hash function implementation for Route object */
namespace std 
{
	template<>
	struct hash<Route> 
	{
		size_t operator()(const Route& route) const noexcept
		{
			return hash<string>()(route.get_url_path());
		}
	};
}
