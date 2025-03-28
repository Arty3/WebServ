#pragma once

#include <string>

#include "configuration/ServerConfiguration.hpp"

class Parse
{
public:
	/**
	* @brief Constructs a Parse object with a configuration file path.
	*
	* Initializes the parser with the specified configuration file path
	* and creates a new ServerConfiguration object.
	*
	* @param file_path Path to the server configuration file
	*/
	explicit Parse(std::string file_path);

	/**
	* @brief Destructor for the Parse object.
	*
	* Frees the dynamically allocated ServerConfiguration object.
	*/
	__attribute__((always_inline)) ~Parse()
	{
		delete server_configuration;
	}

	/**
	* @brief Retrieves the ServerConfiguration object.
	*
	* @return ServerConfiguration* Pointer to the parsed server configuration
	*/
	[[nodiscard]] __attribute__((always_inline))
	ServerConfiguration* get_server_configuration() const
	{
		return server_configuration;
	}

	/**
	* @brief Parses the server configuration file.
	*
	* Reads the configuration file, identifies server blocks,
	* and processes each block to build the server configuration.
	* Validates the final configuration after parsing.
	*/
	void parse_server_configuration_file() const;

private:
	std::string				server_configuration_file_path;
	ServerConfiguration*	server_configuration;

	/**
	* @brief Parses and adds a server listening port from the configuration line.
	*
	* Extracts the port number from the configuration line and adds it to the server configuration.
	*
	* @param line The configuration line containing the port number
	* @throws std::runtime_error If the port number is invalid or cannot be parsed
	*/
	void parse_server_listening_port(const std::string& line) const;

	/**
	* @brief Parses a single server block from the configuration file.
	*
	* Processes a server configuration block by:
	* - Finding the listening port
	* - Parsing location blocks within the server block
	* - Processing other configuration lines
	*
	* @param file_path Input stream of the configuration file
	*/
	void parse_server_block(std::istream& file_path) const;

	/**
	* @brief Parses the server name from the configuration line.
	*
	* Extracts the server name, trims whitespace, and adds it to the server configuration
	* with the current root directory.
	*
	* @param line The configuration line containing the server name
	* @throws std::runtime_error If the server name cannot be parsed
	*/
	void parse_server_name(const std::string& line) const;

	/**
	* @brief Parses the root directory from the configuration line.
	*
	* Extracts and validates the root directory path from the configuration,
	* removing leading/trailing whitespace and ensuring the path is not empty.
	*
	* @param line The configuration line containing the root directory
	* @throws std::runtime_error If the root directory path is invalid or missing
	*/
	void parse_root_directory(const std::string& line) const;

	/**
	* @brief Parses a location block within a server configuration.
	*
	* Processes a location block by:
	* - Extracting the location path
	* - Normalizing the path (removing './', adding leading '/')
	* - Starting a new URL route configuration
	* - Parsing configuration lines within the location block
	* - Ending the URL route configuration when block is complete
	*
	* @param location_line The line containing the location block header
	* @param file_path Input stream of the configuration file
	* @param server_listening_port The port associated with this server block
	*
	* @throws std::runtime_error If location block is improperly formatted
	*/
	void parse_location_block(
		const std::string&	location_line,
		std::istream&		file_path,
		int server_listening_port) const;

	/**
	* @brief Parses the maximum client post request size from the configuration line.
	*
	* Extracts the request size with support for multiple units (bytes, KB, MB):
	* - Handles numeric values with optional 'K' (kilobytes) or 'M' (megabytes)
	* - Converts the size to bytes
	* - Sets the maximum client post request size in the server configuration
	*
	* @param line The configuration line containing the client max post request size
	* @throws std::runtime_error If the request size cannot be parsed or is invalid
	*/
	void parse_max_post_request_size(const std::string& line) const;

	/**
	* @brief Parses the request read buffer size from the configuration line.
	*
	* Extracts the request size with support for multiple units (bytes, KB, MB):
	* - Handles numeric values with optional 'K' (kilobytes) or 'M' (megabytes)
	* - Converts the size to bytes
	* - Sets the maximum client post request size in the server configuration
	*
	* @param line The configuration line containing the request buffer read size
	* @throws std::runtime_error If the request size cannot be parsed or is invalid
	*/
	void parse_request_read_size(const std::string& line) const;

	/**
	* @brief Parses the maximum client request body size from the configuration line.
	*
	* Extracts the body size with support for multiple units (bytes, KB, MB):
	* - Handles numeric values with optional 'K' (kilobytes) or 'M' (megabytes)
	* - Converts the size to bytes
	* - Sets the maximum client request body size in the server configuration
	*
	* @param line The configuration line containing the client max body size
	* @throws std::runtime_error If the body size cannot be parsed or is invalid
	*/
	void parse_client_body_size(const std::string& line) const;

	/**
	* @brief Parses the index file configuration for a specific route.
	*
	* Extracts the index file name from the configuration line and sets it for the current route.
	* Requires the index file to be defined within a location block.
	*
	* @param line The configuration line containing the index file name
	* @throws std::runtime_error If the index file cannot be parsed or is not within a location block
	*/
	void parse_index_file(const std::string& line) const;

	/**
	* @brief Parses the custom error page configuration.
	*
	* Extracts and validates the error page configuration by:
	* - Parsing the HTTP error code
	* - Extracting the error page file path
	* - Verifying the error code is valid
	* - Checking the error page file exists and is accessible
	* - Setting the default error page path in the server configuration
	*
	* @param line The configuration line containing error page details
	* @throws std::runtime_error If the error page configuration is invalid
	*/
	void parse_error_page(const std::string& line) const;

	/**
	* @brief Parses the allowed HTTP methods for a route.
	*
	* Configures the HTTP methods (GET, POST, DELETE) that are permitted for a specific route.
	* Resets existing allowed methods before adding new ones.
	*
	* @param line The configuration line containing allowed HTTP methods
	* @throws std::runtime_error If methods are defined outside a location block or an unknown method is specified
	*/
	void parse_allowed_http_methods(const std::string& line) const;

	/**
	* @brief Parses the directory listing configuration for a route.
	*
	* Enables or disables directory listing within a location block.
	* Only 'on' or 'off' values are accepted.
	*
	* @param line The configuration line containing directory listing setting
	* @throws std::runtime_error If the setting is invalid or not within a location block
	*/
	void parse_directory_listing(const std::string& line) const;

	/**
	* @brief Parses the upload directory configuration for a route.
	*
	* Validates and sets the upload directory by:
	* - Checking the configuration is within a location block
	* - Extracting and cleaning the upload directory path
	* - Ensuring the directory exists, is a directory, and is writable
	*
	* @param line The configuration line containing the upload directory path
	* @throws std::runtime_error If the upload directory is invalid or cannot be used
	*/
	void parse_upload_directory(const std::string& line) const;

	/**
	* @brief Parses the redirect URL configuration for a route.
	*
	* Configures a URL redirection for the current route by:
	* - Checking the configuration is within a location block
	* - Extracting and cleaning the redirect URL
	* - Ensuring the redirect URL is not empty
	* - Setting the redirect URL for the current route
	*
	* @param line The configuration line containing the redirect URL
	* @throws std::runtime_error If the redirect configuration is invalid
	*/
	void parse_redirect(const std::string& line) const;

	/**
	 * @brief Parses the CGI handler configuration for a route.
	 *
	 * Configures a CGI (Common Gateway Interface) handler for a specific file extension by:
	 * - Checking the configuration is within a location block
	 * - Extracting the file extension and executable path
	 * - Ensuring the extension starts with a dot
	 * - Adding the CGI handler to the current route
	 *
	 * @param line The configuration line containing the CGI handler details
	 * @throws std::runtime_error If the CGI handler configuration is invalid
	 */
	void parse_cgi_handler(const std::string& line) const;

	/**
	* @brief Routes configuration lines to their specific parsing functions.
	*
	* Identifies the type of configuration directive and calls the appropriate
	* parsing method for that directive, such as:
	* - Listening port
	* - Server name
	* - Root directory
	* - Client body size
	* - Index file
	* - Error page
	* - Allowed HTTP methods
	* - Directory listing
	* - Redirects
	* - Upload directory
	* - CGI handlers
	*
	* @param line The configuration line to be parsed
	*/
	void parse_line(const std::string& line) const;

	/**
	* @brief Validates the entire server configuration.
	*
	* Checks if the parsed server configuration meets all required criteria.
	* Throws an exception if the configuration is considered invalid.
	*
	* @throws std::runtime_error If the server configuration fails validation checks
	*/
	void validate_configuration() const;
};
