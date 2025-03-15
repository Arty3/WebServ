#pragma once

#include <map>
#include <string>

#include "http/HttpRequest.hpp"
#include "http/HttpResponse.hpp"

class CGIHandler
{
public:
	/**
	* @brief Constructs a CGIHandler object for a specific script and executable.
	*
	* Initializes the CGI handler with the script path and its corresponding
	* executable. Extracts the script's directory path for later use.
	*
	* @param script Full path to the CGI script
	* @param exec Path to the interpreter or executable that will run the script
	*/
	CGIHandler(const std::string& script, const std::string& exec);

	/**
	* @brief Processes a CGI script execution for an HTTP request.
	*
	* Handles the complete lifecycle of executing a CGI script:
	* - Sets up environment variables for the script
	* - Handles POST request body, including chunked transfer
	* - Executes the CGI script
	* - Parses script output, separating headers and body
	* - Populates HTTP response with script output
	* - Manages error scenarios with appropriate HTTP status codes
	*
	* @param request The incoming HTTP request to be processed
	* @param response The HTTP response to be populated with script output
	*/
	void handle_request(const HttpRequest& request, HttpResponse& response) const;

	/**
	 * @brief Determines if the provided filename corresponds to a CGI script.
	 *
	 * This function checks the file extension of the given filename to see
	 * if it matches one of the supported CGI script types: `.php`, `.py`, or `.pl`.
	 *
	 * @param filename The name of the file to check.
	 * @return true if the file is a CGI script, false otherwise.
	 */
	[[nodiscard]]
	static bool is_cgi_file(const std::string& filename);

private:
	mutable std::map<std::string, std::string> environment;

	std::string script_path;
	std::string script_directory;
	std::string cgi_executable;

	/**
	 * @brief Configures the CGI environment variables based on the HTTP request.
	 *
	 * This function sets up the necessary environment variables required for executing
	 * a CGI script. It extracts relevant details from the given HTTP request, such as
	 * the request method, query string, and headers, and maps them to their corresponding
	 * CGI environment variables.
	 *
	 * Key variables configured include:
	 * - `GATEWAY_INTERFACE`: The CGI version being used.
	 * - `SERVER_PROTOCOL`: The HTTP protocol version.
	 * - `REQUEST_METHOD`: The HTTP method (GET or POST).
	 * - `PATH_INFO`: The URL path information before the query string.
	 * - `PATH_TRANSLATED`: The absolute file system path of the script.
	 * - `SCRIPT_NAME` and `SCRIPT_FILENAME`: The script's absolute file path.
	 * - `QUERY_STRING`: The query string from the URL.
	 * - `CONTENT_LENGTH` and `CONTENT_TYPE`: For POST requests, the content's length and type.
	 * - HTTP headers are prefixed with `HTTP_`, converted to uppercase, and hyphens replaced with underscores.
	 *
	 * @param request The HTTP request containing the information to configure the environment.
	 *
	 * @throws std::runtime_error If resolving the real path for the script fails.
	 */
	void setup_environment(const HttpRequest& request) const;

	/**
	 * @brief Executes the CGI script and returns its output.
	 *
	 * This function executes a CGI script using pipes for communication between the parent
	 * and child processes. It writes the request body to the script's standard input (if provided)
	 * and reads the script's output from its standard output. The function handles process creation,
	 * environment setup, and error handling during script execution.
	 *
	 * Steps performed:
	 * - Creates input and output pipes for inter-process communication.
	 * - Forks a child process to execute the CGI script.
	 * - In the child process:
	 *   - Sets up `stdin` and `stdout` to use the pipes.
	 *   - Changes the working directory to the script's directory.
	 *   - Verifies the existence and executability of the script and its interpreter.
	 *   - Executes the CGI script via `execl`.
	 * - In the parent process:
	 *   - Writes the request body to the child process's input pipe (if provided).
	 *   - Reads the script's output from the output pipe.
	 *   - Waits for the child process to complete.
	 *
	 * @param request_body The body of the HTTP request, which is sent to the CGI script if applicable.
	 * @return The output of the CGI script as a string.
	 *
	 * @throws std::runtime_error If:
	 * - Pipes or forking the process fails.
	 * - Writing the request body to the input pipe fails.
	 * - The CGI script execution fails (e.g., non-zero exit status).
	 */
	[[nodiscard]]
	std::string execute_cgi_script(const std::string& request_body) const;

	/**
	 * @brief Converts a chunked HTTP request body into its original, unchunked form.
	 *
	 * This function processes a chunked HTTP request body as per the HTTP/1.1 specification,
	 * decoding it into its original unchunked representation. Each chunk contains a hexadecimal
	 * size followed by the chunk data and ends with a `\r\n`. The function reads each chunk, decodes
	 * its size, and appends the corresponding data to the result string.
	 *
	 * Steps performed:
	 * - Parses the hexadecimal size of each chunk from the input string.
	 * - Reads the specified number of bytes for the chunk data.
	 * - Ignores the trailing `\r\n` after each chunk.
	 * - Stops processing when a chunk of size 0 is encountered, indicating the end of the body.
	 *
	 * @param chunked_body The chunked HTTP request body as a string.
	 * @return The unchunked body as a string.
	 *
	 * @throws std::bad_alloc If memory allocation for chunk data fails.
	 * @throws std::runtime_error If the chunk size is invalid or the data is incomplete.
	 */
	[[nodiscard]]
	std::string unchunk_request_body(const std::string& chunked_body) const;

	/**
	 * @brief Checks if a file exists at the given file path.
	 *
	 * This function uses the `stat` system call to determine whether a file exists
	 * at the specified path. It returns `true` if the file exists and `false` otherwise.
	 *
	 * @param file_path The path to the file to check.
	 * @return true if the file exists, false otherwise.
	 */
	[[nodiscard]]
	bool file_exists(const std::string& file_path) const;
};
