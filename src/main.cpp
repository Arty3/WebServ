#include <cstdlib>
#include <iostream>

#include "configuration/Parse.hpp"
#include "server/Server.hpp"

int main(const int argc, char **argv)
{
	try
	{
		if (argc != 2)
			throw std::runtime_error(
				"Usage: ./webserv [configuration file]"
			);

		const Parse parser{std::string(argv[1])};
		parser.parse_server_configuration_file();

		Server server(parser.get_server_configuration());

		server.setup_server();
		server.start_server();
	}

	catch (const std::exception& e)
	{
		std::cerr	<< "Error: "
					<< e.what()
					<< std::endl;

		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
