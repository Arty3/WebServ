#pragma once

#include <map>
#include <vector>
#include <poll.h>
#include <netinet/in.h>

#include "http/HttpRequest.hpp"
#include "http/HttpResponse.hpp"
#include "configuration/ServerConfiguration.hpp"

class Server
{
public:
	/**
	* @brief Initializes server sockets that listen on the configured ports
	*
	* - Validates server configuration and retrieves list of ports to listen on
	* - For each port:
	*   - Creates a socket using AF_INET (IPv4) and SOCK_STREAM (TCP)
	*   - Sets socket to non-blocking mode using fcntl() for concurrent request handling
	*   - Enables address reuse with setsockopt() to prevent "Address already in use" errors
	*   - Configures socket address (sockaddr_in) with port and INADDR_ANY for all interfaces
	*
	* @param configuration Pointer to the Configuration object containing server settings
	* @throws std::runtime_error If configuration is invalid or socket operations fail
	*/
	explicit Server(const ServerConfiguration* configuration);

	/**
	* Destructor that closes all open server sockets by iterating through the
	* server_file_descriptors vector and calling close() on each file descriptor.
	* This prevents resource leaks by ensuring all network connections are properly terminated.
	*/
	~Server();

	/**
	* @brief Sets up server sockets for each configured port to accept client connections
	*
	* For each port in the configuration:
	* - Creates a socket (AF_INET, SOCK_STREAM)
	* - Enables address reuse via setsockopt()
	* - Binds socket to port using bind()
	* - Starts listening with listen() (backlog queue of 5)
	* - Adds successful sockets to server_file_descriptors
	*
	* If setup fails for a port:
	* - Logs error and continues with next port
	* - Cleans up by closing failed socket
	*
	* @throws std::runtime_error If no ports could be successfully set up
	*/
	void setup_server();

	/**
	* Handles write events for a client socket identified by poll_file_descriptors[index].
	* Gets the client's current HTTP request from our request map and checks if complete.
	* If complete:
	* - Processes request by determining its HTTP method (GET/POST/DELETE)
	* - Changes socket back to read mode (POLLIN) to prepare for next request
	*
	* @param index Position in poll_file_descriptors vector that identifies the client socket
	*/
	void handle_client_write(size_t index);

	/**
	* @brief Starts the server's main event loop
	*
	* - Sets up poll monitoring by initializing poll file descriptors
	* - Prints server configuration info
	* - Enters infinite loop to monitor socket events:
	*   - poll() watches for activity on all file descriptors (blocking, timeout = -1)
	*   - .data() provides contiguous array of poll structs
	*   - .size() gives number of descriptors to monitor
	*   - On successful poll, handle_poll_events() processes active sockets
	*
	* @throws std::runtime_error If poll() system call fails
	*/
	void start_server();

	/**
	* @brief Sets the main server loop flag
	*
	* @param value The flag to determine if the server is running or not
	*/
	__attribute__((always_inline))
	void set_server_running(bool value)
	{
		server_running = value;
	}

	/**
	* @brief Gets the current state of the server loop flag
	*
	* @return bool Current state of the server (true if running, false otherwise)
	*/
	[[nodiscard]] __attribute__((always_inline))
	bool get_server_running()
	{
		return server_running;
	}

private:
	int							main_socket_file_descriptor;
	sockaddr_in					socket_address_configuration;

	std::vector<int>			server_file_descriptors;
	std::vector<pollfd>			poll_file_descriptors;

	std::map<int, HttpRequest>	client_http_requests;
	const ServerConfiguration*	server_configuration;

	bool 						server_running;

	/**
	* @brief Sets up poll file descriptors for monitoring socket events
	*
	* What is polling:
	* - To poll is to check the status (of a device)
	* - The pollfd structure is a standard C-struct used with poll() to monitor multiple file descriptors simultaneously
	* - POLLIN gives the server "ears" to listen to the sockets for detecting new incoming data.
	*
	* Implementation steps:
	* - Clears existing poll_file_descriptors vector
	* - For each server socket in server_file_descriptors:
	*   - Creates a new pollfd structure
	*   - Sets its file descriptor to the server socket
	*   - Enables POLLIN flag to monitor for incoming connections
	*   - Adds structure to poll_file_descriptors vector
	*/
	void setup_poll_file_descriptors();

	/**
	* @brief Handles new incoming client connections on a server socket
	*
	* Core concepts:
	* - accept() creates new socket specifically for this client-server communication
	* - Client's address info is stored in sockaddr_in structure
	* - Non-blocking mode allows handling multiple clients simultaneously
	*
	* Implementation steps:
	* - Accepts new connection, getting dedicated client file descriptor
	* - Sets client socket to non-blocking mode using fcntl
	* - Creates pollfd structure for client with POLLIN flag (ready for reading)
	* - Adds client to poll_file_descriptors vector for monitoring
	* - Initializes empty HTTP request for this client
	*
	* Error handling:
	* - Returns if accept() fails
	* - Closes socket if setting non-blocking mode fails
	*
	* @param server_file_descriptor The listening server socket accepting the connection
	*/
	void handle_incoming_client_connection(int server_file_descriptor);

	/**
	* @brief Handles reading and processing of HTTP requests from a client
	*
	* Core steps:
	* - Reads data from client into 8KB buffer
	* - Updates associated HttpRequest object with new data
	* - Processes different scenarios:
	*
	* Error scenarios (closes connection and cleans up):
	* - Read error (negative bytes_read)
	* - Client disconnection (0 bytes_read)
	* - Payload too large (413 error response)
	*
	* Request processing:
	* - If Content-Length header present:
	*   - Waits until complete body is received
	*   - Processes request when expected length reached
	* - If no Content-Length:
	*   - Processes request when marked complete
	* - After processing, determines HTTP method and removes request from tracking
	*
	* @param index Position in poll_file_descriptors vector of client to read from
	*/
	void handle_http_request_client(size_t index);

	/**
	* @brief Processes events on polled file descriptors (servers and clients)
	*
	* Iterates through poll_file_descriptors checking revents (returned events):
	*
	* Event handling priority:
	* 1. No events (revents == 0):
	*    - Skip to next descriptor
	* 2. Error events (POLLERR | POLLHUP | POLLNVAL):
	*    - Closes socket and removes from monitoring
	*    - POLLERR: Error condition
	*    - POLLHUP: Client disconnected
	*    - POLLNVAL: Invalid descriptor
	* 3. Server socket events:
	*    - If POLLIN: handle_incoming_client_connection()
	* 4. Client socket events:
	*    - If POLLOUT: handle_client_write() for outgoing data
	*    - If POLLIN: handle_http_request_client() for incoming data
	*/
	void handle_poll_events();

	/**
	* @brief Sends HTTP response to client and closes the connection
	*
	* Process:
	* - Builds response string from HttpResponse object
	* - Sends data to client using send() system call
	* - Always closes connection after sending (no keep-alive)
	*
	* Error handling:
	* - If send fails (returns -1 or 0):
	*   - Logs error
	*   - Closes socket
	*   - Removes client from HTTP request tracking
	*   - Removes client from poll monitoring
	*
	* @param client_file_descriptor Socket to send response to
	* @param http_response Response object containing headers and body
	*/
	void send_http_response(int client_file_descriptor, const HttpResponse& http_response);

	/**
	* @brief Processes HTTP request by determining its method and generating appropriate response
	*
	* Processing steps:
	* - Creates empty HTTP response
	* - Gets server port for the client connection
	* - Verifies server configuration exists
	* - Based on HTTP method (GET/POST/DELETE):
	*   - Delegates to appropriate RequestManager handler
	*   - Returns 405 for unsupported methods
	*
	* Error handling:
	* - Returns 500 if server configuration is null
	* - Returns 500 if request handling throws exception
	* - Always sends a response, even on error
	*
	* @param client_file_descriptor Socket connected to the client
	* @param http_request The parsed HTTP request to process
	*/
	void determine_http_method_from_http_request(
		int client_file_descriptor, const HttpRequest& http_request
	);

	/**
	* @brief Gets the port number this socket is listening on
	*
	* Uses getsockname() to retrieve socket information:
	* - Creates sockaddr_in struct to store socket details
	* - Retrieves socket name (address info) via getsockname()
	* - Uses ntohs() which is like rearranging puzzle pieces that were delivered
	*   in network order to your system's order so they fit perfectly in your system.
	*   This is needed because networks and computers might store numbers differently
	*
	* @param socket_file_descriptor Socket to get port number from
	* @return The port number if successful, -1 if getting socket info fails
	*/
	int get_server_listening_port_for_socket(int socket_file_descriptor) const;
};
