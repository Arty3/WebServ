#include <vector>
#include <sstream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <stdexcept>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unordered_set>

#include "server/Server.hpp"
#include "server/RequestManager.hpp"

#include "utils/utils.hpp"

Server::Server(const ServerConfiguration* configuration)
	:	socket_address_configuration{},
		server_configuration(configuration)
{
	if (!server_configuration || !server_configuration->is_valid())
		throw std::runtime_error("Invalid server configuration");

	const std::unordered_set<int> server_listening_ports =
		server_configuration->get_server_listening_ports();

	for (const int server_listening_port : server_listening_ports)
	{
		main_socket_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);

		if (main_socket_file_descriptor < 0)
			throw std::runtime_error(
				"Failed to create main server socket on server listening port "
				+ std::to_string(server_listening_port)
			);

		const int current_socket_flags = fcntl(main_socket_file_descriptor, F_GETFL, 0);

		if (current_socket_flags == -1)
			throw std::runtime_error("Fcntl F_GETFL failed");

		if (fcntl(main_socket_file_descriptor, F_SETFL, current_socket_flags | O_NONBLOCK) == -1)
			throw std::runtime_error("Fcntl F_SETFL failed");

		int enable_reuse_socket_address = 1;

		if (setsockopt(
			main_socket_file_descriptor,
			SOL_SOCKET, SO_REUSEADDR,
			&enable_reuse_socket_address,
			sizeof(enable_reuse_socket_address)) < 0)
			throw std::runtime_error("Setsockopt failed");

		socket_address_configuration.sin_family			= AF_INET;
		socket_address_configuration.sin_addr.s_addr	= INADDR_ANY;
		socket_address_configuration.sin_port			= htons(static_cast
															<short unsigned int>
															(server_listening_port));
	}
}

Server::~Server()
{
	for (const int server_file_descriptor : server_file_descriptors)
		close(server_file_descriptor);
}

void Server::setup_server()
{
	for (const int server_listening_port : server_configuration->get_server_listening_ports())
	{
		int server_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);

		if (server_file_descriptor < 0)
		{
			std::cerr
				<< "ERROR INFO: Failed to create socket for port "
				<< server_listening_port
				<< ": "
				<< strerror(errno)
				<< "\n";

			continue;
		}

		int enable_reuse_socket_address = 1;

		if (setsockopt(
			server_file_descriptor,
			SOL_SOCKET, SO_REUSEADDR,
			&enable_reuse_socket_address,
			sizeof(enable_reuse_socket_address)) < 0)
		{
			std::cerr
				<< "ERROR INFO: Setsockopt failed for port "
				<< server_listening_port
				<< ": "
				<< strerror(errno)
				<< "\n";

			close(server_file_descriptor);
			continue;
		}

		sockaddr_in socket_address = {};

		socket_address.sin_family		= AF_INET;
		socket_address.sin_addr.s_addr	= INADDR_ANY;
		socket_address.sin_port			= htons(static_cast
											<short unsigned int>
											(server_listening_port));

		if (bind(
			server_file_descriptor,
			reinterpret_cast<sockaddr*>(&socket_address),
			sizeof(socket_address)) < 0)
		{
			std::cerr
				<< "ERROR INFO: Failed to bind to port "
				<< server_listening_port
				<< ": "
				<< strerror(errno)
				<< "\n";

			close(server_file_descriptor);
			continue;
		}

		if (listen(server_file_descriptor, 5) < 0)
		{
			std::cerr
				<< "ERROR INFO: Failed to listen on port "
				<< server_listening_port
				<< ": "
				<< strerror(errno)
				<< "\n";

			close(server_file_descriptor);
			continue;
		}

		server_file_descriptors.push_back(server_file_descriptor);
	}

	if (server_file_descriptors.empty())
		throw std::runtime_error(
			"No valid ports to bind and listen to. Exiting..."
		);

	Utils::register_signal_handler(this);
}

void Server::handle_client_write(const size_t index)
{
	const int client_file_descriptor	= poll_file_descriptors[index].fd;
	const HttpRequest& http_request		= client_http_requests[client_file_descriptor];

	if (http_request.is_http_request_complete_check())
	{
		determine_http_method_from_http_request(client_file_descriptor, http_request);
		poll_file_descriptors[index].events = POLLIN;
	}
}

void Server::handle_incoming_client_connection(const int server_file_descriptor)
{
	sockaddr_in client_address;

	socklen_t client_address_length		= sizeof(client_address);
	const int client_file_descriptor	= accept(
											server_file_descriptor,
											reinterpret_cast<sockaddr*>(&client_address),
											&client_address_length);

	if (client_file_descriptor < 0)
	{
		std::cerr
			<< "ERROR INFO: Failed to accept client connection on server socket "
			<< server_file_descriptor
			<< ". Error: "
			<< strerror(errno)
			<< "\n";

		return;
	}

	const int current_socket_status_flags = fcntl(client_file_descriptor, F_GETFL, 0);

	if (current_socket_status_flags == -1 || fcntl(
			client_file_descriptor, F_SETFL,
			current_socket_status_flags | O_NONBLOCK
		) == -1)
	{
		std::cerr
			<< "ERROR INFO: Failed to set client socket "
			<< client_file_descriptor
			<< " to non-blocking mode.\n";

		close(client_file_descriptor);
		return;
	}

	pollfd client_poll_file_descriptor	= {};

	client_poll_file_descriptor.fd		= client_file_descriptor;
	client_poll_file_descriptor.events	= POLLIN;

	poll_file_descriptors.push_back(client_poll_file_descriptor);

	client_http_requests[client_file_descriptor] = HttpRequest();

	std::cout
		<< "INFO: New client connection accepted on socket "
		<< server_file_descriptor
		<< "\n";
}

void Server::handle_http_request_client(const size_t index)
{
	/* Ensure no stack issues */
	char buffer[_MAX_REQUEST_READ_SIZE];

	const size_t read_size	= server_configuration->get_request_read_size() > _MAX_REQUEST_READ_SIZE
							? _MAX_REQUEST_READ_SIZE : server_configuration->get_request_read_size();

	const int client_file_descriptor = poll_file_descriptors[index].fd;

	HttpRequest& http_request = client_http_requests[client_file_descriptor];

	ssize_t	bytes_read = read(client_file_descriptor, buffer, read_size);

	if (bytes_read < 0)
	{
		std::cerr
			<< "ERROR: Failed to read from client. Client FD: "
			<< client_file_descriptor
			<< "\n";

		close(client_file_descriptor);

		poll_file_descriptors.erase(poll_file_descriptors.begin()
			+ static_cast<std::vector<pollfd>::difference_type>(index));
		client_http_requests.erase(client_file_descriptor);

		return;
	}

	bool is_http_request_complete = http_request.process_incoming_http_request(
		std::string(buffer, static_cast<size_t>(bytes_read))
	);

	if (!is_http_request_complete)
	{
		if (!bytes_read)
			std::cerr
				<< "INFO: Client disconnected before sending complete request. Client FD: "
				<< client_file_descriptor
				<< "\n";
		else
			std::cerr
				<< "INFO: Invalid HTTP request from client. Client FD: "
				<< client_file_descriptor
				<< "\n";

		close(client_file_descriptor);

		poll_file_descriptors.erase(poll_file_descriptors.begin()
			+ static_cast<std::vector<pollfd>::difference_type>(index));
		client_http_requests.erase(client_file_descriptor);
	}

	if (is_http_request_complete && http_request.get_http_request_body() == "413 Payload Too Large")
	{
		HttpResponse http_response;
		http_response.set_http_response_status_code(HttpStatusCode::HTTP_413_PAYLOAD_TOO_LARGE);
		http_response.set_http_response_content_type("text/html");
		http_response.set_http_response_body(
			"<html><body><h1>413 Payload Too Large</h1><p>File too large. Maximum size is 10MB.</p></body></html>"
		);

		send_http_response(client_file_descriptor, http_response);
	
		close(client_file_descriptor);

		poll_file_descriptors.erase(poll_file_descriptors.begin()
			+ static_cast<std::vector<pollfd>::difference_type>(index));
		client_http_requests.erase(client_file_descriptor);

		return;
	}

	if (http_request.has_http_request_header("Content-Length"))
	{
		const size_t expected_http_request_length = std::stoul(
			http_request.get_http_request_header("Content-Length")
		);

		if (is_http_request_complete && http_request.get_http_request_body().length() >= expected_http_request_length)
		{
			determine_http_method_from_http_request(client_file_descriptor, http_request);
			client_http_requests.erase(client_file_descriptor);
		}
		else
			poll_file_descriptors[index].events = POLLIN;
	}
	else if (is_http_request_complete)
	{
		determine_http_method_from_http_request(client_file_descriptor, http_request);
		client_http_requests.erase(client_file_descriptor);
	}
}

void Server::send_http_response(
	const int			client_file_descriptor,
	const HttpResponse&	http_response)
{
	const std::string http_response_string = http_response.build_http_response();

	const ssize_t bytes_sent = send(
		client_file_descriptor,
		http_response_string.c_str(),
		http_response_string.length(),
		0
	);

	if (bytes_sent <= 0)
	{
		std::cerr
			<< "ERROR INFO: Failed to send HTTP response to client."
			<< "\n";

		close(client_file_descriptor);
		client_http_requests.erase(client_file_descriptor);

		for (size_t i = 0; i < poll_file_descriptors.size(); ++i)
		{
			if (poll_file_descriptors[i].fd == client_file_descriptor)
			{
				poll_file_descriptors.erase(poll_file_descriptors.begin()
					+ static_cast<std::vector<pollfd>::difference_type>(i));

				break;
			}
		}

		return;
	}

	close(client_file_descriptor);
	client_http_requests.erase(client_file_descriptor);

	for (size_t i = 0; i < poll_file_descriptors.size(); ++i)
	{
		if (poll_file_descriptors[i].fd == client_file_descriptor)
		{
			poll_file_descriptors.erase(poll_file_descriptors.begin()
				+ static_cast<std::vector<pollfd>::difference_type>(i));

			break;
		}
	}
}

int Server::get_server_listening_port_for_socket(const int socket_file_descriptor) const
{
	sockaddr_in socket_address;
	socklen_t socket_adress_length = sizeof(socket_address);

	if (getsockname(
		socket_file_descriptor,
		reinterpret_cast<sockaddr*>(&socket_address),
		&socket_adress_length) == -1)
	{
		std::cerr
			<< "ERROR INFO: Failed to retrieve socket information. Socket FD: "
			<< socket_file_descriptor
			<< "\n";

		return -1;
	}

	return ntohs(socket_address.sin_port);
}

void Server::determine_http_method_from_http_request(
	const int			client_file_descriptor,
	const HttpRequest&	http_request)
{
	HttpResponse http_response;

	const int server_listening_port =
		get_server_listening_port_for_socket(client_file_descriptor);

	if (!server_configuration)
	{
		std::cerr << "ERROR INFO: Configuration is null!\n";

		http_response.set_http_response_status_code(HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR);
		send_http_response(client_file_descriptor, http_response);

		return;
	}

	const RequestManager request_manager(server_configuration);

	try
	{
		switch (http_request.get_http_request_method())
		{
		case HttpMethod::GET:
			request_manager.handle_http_get_request(
				http_request.get_http_request_url(),
				http_request, http_response,
				server_listening_port
			);
			break;

		case HttpMethod::POST:
			request_manager.handle_http_post_request(
				http_request.get_http_request_url(),
				http_request, http_response,
				server_listening_port
			);
			break;

		case HttpMethod::DELETE:
			request_manager.handle_http_delete_request(
				http_request.get_http_request_url(),
				http_response,
				server_listening_port
			);
			break;

		default:
			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_405_METHOD_NOT_ALLOWED
			);
		}
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: Failed to determine HTTP method for HTTP request: "
			<< e.what()
			<< "\n";

		http_response.set_http_response_status_code(
			HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
		);
	}

	send_http_response(client_file_descriptor, http_response);
}

void Server::setup_poll_file_descriptors()
{
	if (!poll_file_descriptors.size())
		poll_file_descriptors.clear();

	for (const int server_file_descriptor : server_file_descriptors)
	{
		pollfd server_poll_file_descriptor	= {};

		server_poll_file_descriptor.fd		= server_file_descriptor;
		server_poll_file_descriptor.events	= POLLIN;

		poll_file_descriptors.push_back(server_poll_file_descriptor);
	}
}

void Server::handle_poll_events()
{
	for (size_t i = 0; i < poll_file_descriptors.size(); ++i)
	{
		if (!poll_file_descriptors[i].revents)
			continue;

		if (poll_file_descriptors[i].revents & (POLLERR | POLLHUP | POLLNVAL))
		{
			close(poll_file_descriptors[i].fd);

			poll_file_descriptors.erase(
				poll_file_descriptors.begin() +
				static_cast<std::vector<pollfd>::difference_type>(i)
			);

			continue;
		}

		if (std::find(
				server_file_descriptors.begin(),
				server_file_descriptors.end(),
				poll_file_descriptors[i].fd
			) != server_file_descriptors.end())
		{
			if (poll_file_descriptors[i].revents & POLLIN)
				handle_incoming_client_connection(poll_file_descriptors[i].fd);

			continue;
		}

		/* Double if instead of else if for concurrency */

		if (poll_file_descriptors[i].revents & POLLOUT)
			handle_client_write(i);

		if (poll_file_descriptors[i].revents & POLLIN)
			handle_http_request_client(i);
	}
}

void Server::start_server()
{
	setup_poll_file_descriptors();

	std::cout << "Server successfully initialized.\n";
	std::cout << server_configuration->get_server_configuration_string() << "\n";
	std::cout << "Ready.\n\n";

	set_server_running(true);

	while (server_running)
	{
		const int poll_result = poll(
			poll_file_descriptors.data(),
			poll_file_descriptors.size(),
			-1
		);

		if (poll_result < 0)
			throw std::runtime_error(
				"Poll syscall failed."
			);

		handle_poll_events();
	}
}
