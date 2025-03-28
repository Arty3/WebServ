#include "utils/utils.hpp"

#include <stdexcept>
#include <iostream>
#include <csignal>
#include <cstdlib>

#include "server/Server.hpp"

static Server* __g_instance = nullptr;

static void SignalHandler(int __signo)
{
	std::cout << "\nInterrupt signal (" << __signo << ") received.\n";
	if (__g_instance) __g_instance->set_server_running(false);

	/* By this point no leaks should exist */
	std::exit(EXIT_SUCCESS);
}

void Utils::register_signal_handler(Server* instance)
{
	__g_instance = instance;

	if (std::signal(SIGINT, SignalHandler) == SIG_ERR)
		throw std::runtime_error(
			"Failed to register SIGINT signal handler"
		);

	if (std::signal(SIGQUIT, SignalHandler) == SIG_ERR)
		throw std::runtime_error(
			"Failed to register SIGQUIT signal handler"
		);
}
