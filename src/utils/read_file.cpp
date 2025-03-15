#include "utils/utils.hpp"

#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <string>

std::string Utils::read_file(const std::string& file_path)
{
	const int file_descriptor = open(file_path.c_str(), O_RDONLY | O_NONBLOCK);

	if (file_descriptor < 0)
		throw std::runtime_error(
			"Failed to open file: " + file_path
		);

	char buffer[Utils::_READ_SIZE];

	std::string	content;
	ssize_t		bytes_read;

	while ((bytes_read = read(file_descriptor, buffer, sizeof(buffer))) > 0)
		content.append(buffer, static_cast<size_t>(bytes_read));

	if (bytes_read == -1)
	{
		close(file_descriptor);
		throw std::runtime_error(
			"Error reading file: " + file_path
		);
	}

	close(file_descriptor);

	return content;
}