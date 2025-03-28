#pragma once

#include "server/Server.hpp"

#include <string>

namespace Utils
{
	static constexpr const inline size_t _READ_SIZE = 4096; /* 1 page */

	/**
	 * Reads entire contents of a file into a string using a 4KB buffer. Opens file in
	 * read-only mode, reads chunks until EOF or error, then closes file. Throws if file
	 * can't be opened or read error occurs.
	 *
	 * @param file_path Path to the file to read
	 * @return String containing entire file contents
	 * @throws std::runtime_error If file operations fail
	 */
	std::string read_file(const std::string& file_path);

	/**
	 * Registers a signal handler function for SIGINT and SIGQUIT
	 * such that the server can exit gracefully.
	 *
	 * @param instance The server instance required to stop it
	 * 
	 * @throws std::runtime_error If assigning the handler fails
	 */
	void register_signal_handler(Server* instance);
}
