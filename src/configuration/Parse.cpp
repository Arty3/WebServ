#include <fcntl.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <charconv>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <unordered_map>

#include "configuration/Parse.hpp"
#include "utils/utils.hpp"

static inline bool is_path_safe(const std::string& path)
{
	if (path.find("../")	!= std::string::npos	|| 
		path.find("..\\")	!= std::string::npos	||
		path.find("./..")	!= std::string::npos	||
		path.find(".\\..")	!= std::string::npos	||
		path == ".."								|| 
		path == ".")
		return false;
		
	if (path.find("//") != std::string::npos)
		return false;

	return true;
}

Parse::Parse(std::string file_path)
	:	server_configuration_file_path(std::move(file_path)),
		server_configuration(new ServerConfiguration())
{
	namespace fs = std::filesystem;

	if (!fs::exists(server_configuration_file_path) ||
		!fs::is_regular_file(server_configuration_file_path))
		throw std::runtime_error(
			"Invalid configuration file path provided."
		);
}

void Parse::parse_server_configuration_file() const
{
	const std::string server_configuration_content =
		Utils::read_file(server_configuration_file_path);

	std::istringstream	server_configuration_stream(server_configuration_content);
	std::string			line;

	while(std::getline(server_configuration_stream, line))
		if (line.find("server") != std::string::npos)
			parse_server_block(server_configuration_stream);

	validate_configuration();
}

void Parse::parse_server_block(std::istream& file_path) const
{
	if (!file_path.good())
		throw std::runtime_error(
			"Invalid argument provided."
		);
		
	const std::streampos start_position = file_path.tellg();

	if (start_position == std::streampos(-1))
		throw std::runtime_error(
			"Error getting stream position in server block"
		);

	int		server_listening_port	= 0;
	bool	found_listen_directive	= false;

	std::string first_line;

	while (std::getline(file_path, first_line))
	{
		if (first_line.empty())
			continue;
			
		if (first_line.find("listen") != std::string::npos)
		{
			size_t last_space = first_line.find_last_of(" \t");

			if (last_space == std::string::npos ||
				last_space >= first_line.length() - 1)
				throw std::runtime_error(
					"Invalid listen directive format"
				);
				
			try
			{
				std::string port_str = first_line.substr(last_space + 1);

				size_t		idx = 0;
				const long	tmp = std::stol(port_str, &idx);

				if (tmp < std::numeric_limits<int>::min() ||
					tmp > std::numeric_limits<int>::max())
					throw std::runtime_error(
						"Invalid port value, must be within the integer range"
					);

				while (!port_str.empty() && std::isspace(port_str.back()))
					port_str.pop_back();

				if (port_str.ends_with(";"))
					port_str = port_str.substr(0, port_str.size() - 1);

				if (idx != port_str.length())
					throw std::runtime_error(
						"Invalid port value, must be a positive number"
					);

				server_listening_port = static_cast<int>(tmp);
				found_listen_directive = true;
			}

			catch (const std::exception& e)
			{
				throw std::runtime_error(
					"Invalid port number in listen directive: "
					+ std::string(e.what())
				);
			}

			break;
		}
	}
	
	if (!found_listen_directive)
		throw std::runtime_error(
			"Missing listen directive in server block"
		);

	if (!file_path.good())
		throw std::runtime_error(
			"Error in file stream after finding listen directive"
		);
		
	file_path.seekg(start_position);
	std::streampos seek_result = file_path.tellg();

	if (seek_result == std::streampos(-1))
		throw std::runtime_error(
			"Error seeking to start position in server block"
		);

	std::string line;

	while (std::getline(file_path, line))
	{
		if (line.empty())
			continue;
			
		if (line.find('}') != std::string::npos)
			break;

		if (line.find("location") != std::string::npos)
			parse_location_block(line, file_path, server_listening_port);

		else
			parse_line(line);
	}
}

void Parse::parse_location_block(
	const std::string&	location_line,
	std::istream&		file_path,
	const int			server_listening_port) const
{
	if (location_line.empty() || !file_path.good() || server_listening_port < 1)
		throw std::runtime_error(
			"Invalid argument provided."
		);

	const size_t location_keyword_start_index = location_line.find("location");

	if (location_keyword_start_index == std::string::npos)
		throw std::runtime_error(
			"Location block missing location keyword"
		);

	const size_t location_keyword_length = sizeof("location") - 1;

	if (location_keyword_start_index > std::string::npos - location_keyword_length)
		throw std::runtime_error(
			"Invalid file path value found, potentially causes vulnerability"
		);

	const size_t location_file_path_start_index = location_keyword_start_index
												+ location_keyword_length;

	const size_t location_file_path_end_index = location_line.find('{');

	if (location_file_path_end_index == std::string::npos)
		throw std::runtime_error(
			"Location block missing opening brace"
		);

	if (location_file_path_end_index < location_file_path_start_index)
		throw std::runtime_error(
			"Invalid file path value found, potentially causes vulnerability"
		);

	std::string location_file_path = location_line.substr(
		location_file_path_start_index,
		location_file_path_end_index - location_file_path_start_index
	);

	size_t first_not_space = location_file_path.find_first_not_of(" \t");

	if (first_not_space == std::string::npos)
		throw std::runtime_error(
			"Location path contains only whitespace"
		);
	
	location_file_path = location_file_path.substr(first_not_space);
	
	if (location_file_path.empty())
		throw std::runtime_error(
			"Location path is empty after trimming whitespace"
		);

	size_t last_not_space = location_file_path.find_last_not_of(" \t");

	if (last_not_space == std::string::npos)
		throw std::runtime_error(
			"Location path contains only whitespace"
		);
	
	location_file_path = location_file_path.substr(0, last_not_space + 1);

	if (location_file_path.length() >= 2 &&
		location_file_path.starts_with("./"))
		location_file_path = location_file_path.substr(2);

	if (location_file_path.empty())
		throw std::runtime_error(
			"Location path is empty after removing ./"
		);

	if (location_file_path[0] != '/')
		location_file_path = "/" + location_file_path;

	server_configuration->start_url_route(
		location_file_path, server_listening_port
	);

	std::string line;
	bool found_closing_brace = false;
	
	while (std::getline(file_path, line))
	{
		if (!file_path.good() && !file_path.eof())
			throw std::runtime_error(
				"Error reading location block content"
			);
			
		if (line.find('}') != std::string::npos)
		{
			server_configuration->end_url_route();
			found_closing_brace = true;
			break;
		}
		parse_line(line);
	}
	
	if (!found_closing_brace)
		throw std::runtime_error(
			"Location block missing closing brace"
		);
}

void Parse::parse_server_listening_port(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t position = line.find_last_of(" \t");

		if (position == std::string::npos || position >= line.length() - 1)
			throw std::runtime_error(
				"Invalid server listening port format"
			);

		std::string port_str = line.substr(position + 1);

		size_t		idx	= 0;
		const long	tmp	= std::stol(port_str, &idx);

		if (tmp < std::numeric_limits<int>::min() ||
			tmp > std::numeric_limits<int>::max())
			throw std::runtime_error(
				"Port number out of int range."
			);

		while (!port_str.empty() && std::isspace(port_str.back()))
			port_str.pop_back();

		if (port_str.ends_with(";"))
			port_str = port_str.substr(0, port_str.size() - 1);
	
		if (idx != port_str.length())
			throw std::runtime_error(
				"Invalid port value, must be a positive number"
			);
	
		const int server_listening_port_number = static_cast<int>(tmp);

		if (server_listening_port_number < 1)
			throw std::runtime_error(
				"Invalid server listening port, should be 1 or above"
			);

		server_configuration->add_server_listening_port(
			static_cast<unsigned int>(server_listening_port_number)
		);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Invalid server listening port number in configuration: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_root_directory(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t			root_directory_path_start_index	= line.find("root");
		const size_t	root_directory_path_end_index	= line.find(';');

		if (root_directory_path_start_index == std::string::npos)
			throw std::runtime_error(
				"Root keyword not found"
			);

		root_directory_path_start_index += 4;

		if (root_directory_path_end_index == std::string::npos)
			throw std::runtime_error(
				"Invalid root directory format: Missing semicolon"
			);

		if (root_directory_path_start_index >= line.length())
			throw std::runtime_error(
				"Invalid root directory format"
			);

		if (root_directory_path_end_index <= root_directory_path_start_index)
			throw std::runtime_error(
				"Invalid root directory format: Empty path"
			);

		std::string root_directory_path = line.substr(
			root_directory_path_start_index,
			root_directory_path_end_index - root_directory_path_start_index
		);

		root_directory_path = root_directory_path.substr(
			root_directory_path.find_first_not_of(" \t")
		);

		root_directory_path = root_directory_path.substr(
			0, root_directory_path.find_last_not_of(" \t") + 1
		);

		if (root_directory_path.empty())
			throw std::runtime_error(
				"Root directory path is missing or empty"
			);

		if (!is_path_safe(root_directory_path))
			throw std::runtime_error(
				"Root directory path contains potentially unsafe path traversal"
			);

		server_configuration->set_root_directory(root_directory_path);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing root directory: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_server_name(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t name_start = line.find("server_name");

		if (name_start == std::string::npos)
			throw std::runtime_error(
				"Server name keyword not found"
			);
			
		name_start += sizeof("server_name") - 1;

		if (name_start >= line.length())
			throw std::runtime_error(
				"Invalid server name format"
			);

		std::string server_name = line.substr(name_start);
		
		size_t semicolon_pos = server_name.find(';');

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid server name format: Missing semicolon"
			);
			
		server_name = server_name.substr(0, semicolon_pos);
		
		size_t name_first = server_name.find_first_not_of(" \t");

		if (name_first == std::string::npos)
			throw std::runtime_error(
				"Server name is empty"
			);
			
		server_name = server_name.substr(name_first);
		
		size_t name_last = server_name.find_last_not_of(" \t");

		if (name_last == std::string::npos)
			throw std::runtime_error(
				"Server name contains only whitespace"
			);
			
		server_name = server_name.substr(0, name_last + 1);

		server_configuration->add_server_name(
			server_name,
			server_configuration->get_root_directory()
		);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing server name: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_max_post_request_size(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t size_start = line.find("client_max_post_request_size");

		if (size_start == std::string::npos)
			throw std::runtime_error(
				"Max post request size keyword not found"
			);
			
		size_start += sizeof("client_max_post_request_size") - 1;

		if (size_start >= line.length())
			throw std::runtime_error(
				"Invalid max post request size format"
			);

		std::string size_string = line.substr(size_start);
		
		size_t first_not_space = size_string.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Max post request size is empty"
			);
			
		size_string = size_string.substr(first_not_space);
		
		size_t first_digit = size_string.find_first_of("0123456789");

		if (first_digit == std::string::npos)
			throw std::runtime_error(
				"Max post request size contains no digits"
			);
			
		size_string = size_string.substr(first_digit);
		
		size_t semicolon_pos = size_string.find(';');

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid max post request size format: Missing semicolon"
			);
			
		size_string = size_string.substr(0, semicolon_pos);

		size_t multiplier = 1;

		if (!size_string.empty())
		{
			if (size_string.back() == 'M')
				multiplier = 1024 * 1024;

			else if (size_string.back() == 'K')
				multiplier = 1024;

			if (!std::isdigit(size_string.back()))
				size_string.pop_back();
		}

		else
			throw std::runtime_error(
				"Max post request size is empty after parsing"
			);

		size_t tmp;

		auto[ptr, ec] = std::from_chars(
			size_string.data(),
			size_string.data() + size_string.size(),
			tmp
		);

		if (ec == std::errc())
			if (tmp > std::numeric_limits<size_t>::max() / multiplier)
				throw std::runtime_error(
					"Max post request size is out of range"
				);

		server_configuration->set_max_post_request_size(tmp * multiplier);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Invalid client_max_post_request_size: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_client_body_size(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t size_start = line.find("client_max_body_size");

		if (size_start == std::string::npos)
			throw std::runtime_error(
				"Max body size keyword not found"
			);
			
		size_start += sizeof("client_max_body_size") - 1;

		if (size_start >= line.length())
			throw std::runtime_error(
				"Invalid max body size format"
			);

		size_t semicolon_pos = line.find(';', size_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid max body size format: Missing semicolon"
			);
		
		std::string size_string = line.substr(
			size_start, semicolon_pos - size_start
		);
		
		size_t first_not_space = size_string.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Max body size is empty"
			);
			
		size_string = size_string.substr(first_not_space);
		
		size_t first_digit = size_string.find_first_of("0123456789");

		if (first_digit == std::string::npos)
			throw std::runtime_error(
				"Max body size contains no digits"
			);
			
		size_string = size_string.substr(first_digit);

		size_t multiplier = 1;

		if (!size_string.empty())
		{
			if (size_string.back() == 'M')
				multiplier = 1024 * 1024;

			else if (size_string.back() == 'K')
				multiplier = 1024;

			if (!std::isdigit(size_string.back()))
				size_string.pop_back();
				
			if (size_string.empty())
				throw std::runtime_error(
					"Max body size has no digits after removing suffix"
				);
		}

		else
			throw std::runtime_error(
				"Max body size is empty after parsing"
			);

		size_t tmp;

		auto[ptr, ec] = std::from_chars(
			size_string.data(),
			size_string.data() + size_string.size(),
			tmp
		);

		if (ec == std::errc())
			if (tmp > std::numeric_limits<size_t>::max() / multiplier)
				throw std::runtime_error(
					"Max post request size is out of range"
				);

		server_configuration->set_max_request_body_size(tmp * multiplier);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Invalid client_max_body_size: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_request_read_size(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t size_start = line.find("request_read_buffer_size");

		if (size_start == std::string::npos)
			throw std::runtime_error(
				"Read buffer size keyword not found"
			);
			
		size_start += sizeof("request_read_buffer_size") - 1;

		if (size_start >= line.length())
			throw std::runtime_error(
				"Invalid read buffer size format"
			);

		size_t semicolon_pos = line.find(';', size_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid read buffer size format: Missing semicolon"
			);
			
		std::string size_string = line.substr(size_start, semicolon_pos - size_start);

		size_t first_not_space = size_string.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Read buffer size is empty"
			);
			
		size_string = size_string.substr(first_not_space);

		if (size_string == "default")
			return;

		size_t first_digit = size_string.find_first_of("0123456789");

		if (first_digit == std::string::npos)
			throw std::runtime_error(
				"Read buffer size contains no digits"
			);
			
		size_string = size_string.substr(first_digit);

		size_t multiplier = 1;

		if (!size_string.empty())
		{
			if (size_string.back() == 'M')
				multiplier = 1024 * 1024;

			else if (size_string.back() == 'K')
				multiplier = 1024;

			if (!std::isdigit(size_string.back()))
				size_string.pop_back();
				
			if (size_string.empty())
				throw std::runtime_error(
					"Read buffer size has no digits after removing suffix"
				);
		}

		else
			throw std::runtime_error(
				"Read buffer size is empty after parsing"
			);

		size_t tmp;

		auto[ptr, ec] = std::from_chars(
			size_string.data(),
			size_string.data() + size_string.size(),
			tmp
		);

		if (ec == std::errc())
			if (tmp > std::numeric_limits<size_t>::max() / multiplier)
				throw std::runtime_error(
					"Max post request size is out of range"
				);

		server_configuration->set_max_request_body_size(tmp * multiplier);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Invalid client_max_body_size: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_index_file(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Index must be defined within a location block"
			);

		size_t index_start = line.find("index");

		if (index_start == std::string::npos)
			throw std::runtime_error(
				"Index keyword not found"
			);
			
		index_start += sizeof("index") - 1;

		if (index_start >= line.length())
			throw std::runtime_error(
				"Invalid index file format"
			);

		size_t semicolon_pos = line.find(';', index_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid index file format: Missing semicolon"
			);
			
		std::string index_file_path = line.substr(
			index_start, semicolon_pos - index_start
		);

		size_t first_not_space = index_file_path.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Index file path contains only whitespace"
			);
			
		index_file_path = index_file_path.substr(first_not_space);
		
		size_t last_not_space = index_file_path.find_last_not_of(" \t");

		if (last_not_space == std::string::npos)
			throw std::runtime_error(
				"Index file path contains only whitespace"
			);
			
		index_file_path = index_file_path.substr(0, last_not_space + 1);

		if (index_file_path.empty())
			throw std::runtime_error(
				"Index file name is missing or empty"
			);

		if (!is_path_safe(index_file_path))
			throw std::runtime_error(
				"Index file path contains potentially unsafe path traversal"
			);

		current_url_route->set_index_file(index_file_path);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing index file: " + std::string(e.what())
		);
	}
}

void Parse::parse_error_page(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		size_t error_start = line.find("error_page");

		if (error_start == std::string::npos)
			throw std::runtime_error(
				"Error page keyword not found"
			);
			
		error_start += sizeof("error_page") - 1;

		if (error_start >= line.length())
			throw std::runtime_error(
				"Invalid error page format"
			);

		const std::string content = line.substr(error_start);

		if (content.empty())
			throw std::runtime_error(
				"Error page content is empty"
			);

		std::istringstream content_stream(content);
		std::string error_page_file_path;

		int error_code;

		if (!(content_stream >> error_code >> error_page_file_path))
			throw std::runtime_error(
				"Invalid error page format"
			);

		if (error_page_file_path.back() == ';')
			error_page_file_path.pop_back();

		if (error_code < 100 || error_code > 599)
			throw std::runtime_error(
				"Invalid HTTP error code: "
				+ std::to_string(error_code)
			);

		if (error_page_file_path.empty())
			throw std::runtime_error(
				"Error page path is empty"
			);

		std::string root_path = server_configuration->get_root_directory();

		if (root_path.starts_with("./"))
			root_path = root_path.substr(2);

		if (error_page_file_path.starts_with("./"))
			error_page_file_path = error_page_file_path.substr(2);

		if (!is_path_safe(error_page_file_path))
			throw std::runtime_error(
				"Error page path contains potentially unsafe path traversal"
			);

		const std::string full_path = root_path + "/"
									+ error_page_file_path;

		try
		{
			std::string save_file_content_of_read_file_check = Utils::read_file(full_path);
		}
		catch (const std::runtime_error&)
		{
			throw std::runtime_error(
				"Error page file not found or not accessible: " + full_path
			);
		}

		server_configuration->set_default_error_page_path(error_page_file_path);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing error page: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_directory_listing(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Directory listing must be defined within a location block"
			);

		size_t listing_start = line.find("directory_listing");

		if (listing_start == std::string::npos)
			throw std::runtime_error(
				"Directory listing keyword not found"
			);
			
		listing_start += sizeof("directory_listing") - 1;

		if (listing_start >= line.length())
			throw std::runtime_error(
				"Invalid directory listing format"
			);

		size_t semicolon_pos = line.find(';', listing_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid directory listing format: Missing semicolon"
			);
			
		std::string value = line.substr(
			listing_start, semicolon_pos - listing_start
		);

		size_t first_not_space = value.find_first_not_of(" \t");
		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Directory listing value contains only whitespace"
			);
			
		value = value.substr(first_not_space);

		if (value.length() < 2)
			throw std::runtime_error(
				"Directory listing value too short"
			);

		/* Note lowercase is explicit */
		if (value.starts_with("on"))
			current_url_route->set_directory_listing(true);

		else if (value.starts_with("off"))
			current_url_route->set_directory_listing(false);

		else
			throw std::runtime_error(
				"Error parsing directory listing. Options are 'on' or 'off'"
			);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing directory listing: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_allowed_http_methods(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Allowed HTTP methods must be defined within a location block"
			);

		size_t methods_start = line.find("allowed_methods");

		if (methods_start == std::string::npos)
			throw std::runtime_error(
				"Allowed methods keyword not found"
			);
			
		methods_start += sizeof("allowed_methods") - 1;

		if (methods_start >= line.length())
			throw std::runtime_error(
				"Invalid allowed methods format"
			);

		size_t semicolon_pos = line.find(';', methods_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid allowed methods format: Missing semicolon"
			);
			
		std::string http_methods = line.substr(
			methods_start, semicolon_pos - methods_start
		);

		size_t first_not_space = http_methods.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"No HTTP methods specified"
			);
			
		http_methods = http_methods.substr(first_not_space);
		
		size_t last_not_space = http_methods.find_last_not_of(" \t");

		if (last_not_space == std::string::npos)
			throw std::runtime_error(
				"HTTP methods contain only whitespace"
			);
			
		http_methods = http_methods.substr(0, last_not_space + 1);

		current_url_route->remove_allowed_http_method(HttpMethod::GET);
		current_url_route->remove_allowed_http_method(HttpMethod::POST);
		current_url_route->remove_allowed_http_method(HttpMethod::DELETE);

		std::istringstream http_methods_stream(http_methods);
		std::string http_method;
		bool found_method = false;

		while (http_methods_stream >> http_method)
		{
			found_method = true;
			
			if (http_method == "GET")
				current_url_route->add_allowed_http_method(HttpMethod::GET);

			else if (http_method == "POST")
				current_url_route->add_allowed_http_method(HttpMethod::POST);

			else if (http_method == "DELETE")
				current_url_route->add_allowed_http_method(HttpMethod::DELETE);

			else
				throw std::runtime_error(
					"Unknown HTTP method: " + http_method
				);
		}
		
		if (!found_method)
			throw std::runtime_error(
				"No valid HTTP methods specified"
			);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing allowed HTTP methods: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_upload_directory(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Upload directory must be defined within a location block"
			);

		size_t upload_start = line.find("upload_directory");

		if (upload_start == std::string::npos)
			throw std::runtime_error(
				"Upload directory keyword not found"
			);
			
		upload_start += sizeof("upload_directory") - 1;

		if (upload_start >= line.length())
			throw std::runtime_error(
				"Invalid upload directory format"
			);

		size_t semicolon_pos = line.find(';', upload_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid upload directory format: Missing semicolon"
			);
			
		std::string upload_directory_path = line.substr(
			upload_start, semicolon_pos - upload_start
		);

		size_t first_not_space = upload_directory_path.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Upload directory path contains only whitespace"
			);
			
		upload_directory_path = upload_directory_path.substr(first_not_space);
		
		size_t last_not_space = upload_directory_path.find_last_not_of(" \t");

		if (last_not_space == std::string::npos)
			throw std::runtime_error(
				"Upload directory path contains only whitespace"
			);
			
		upload_directory_path = upload_directory_path.substr(0, last_not_space + 1);

		if (upload_directory_path.empty())
			throw std::runtime_error(
				"Upload directory path is missing or empty"
			);

		std::string root_directory_path = server_configuration->get_root_directory();

		if (root_directory_path.empty())
			throw std::runtime_error(
				"Root directory path is missing or empty"
			);

		if (root_directory_path.starts_with("./"))
			root_directory_path = root_directory_path.substr(2);
		
		if (upload_directory_path.starts_with("./"))
			upload_directory_path = upload_directory_path.substr(2);

		if (upload_directory_path.starts_with("www/"))
			upload_directory_path = upload_directory_path.substr(4);

		if (!is_path_safe(upload_directory_path))
			throw std::runtime_error(
				"Upload directory path contains potentially unsafe path traversal"
			);

		const std::string full_path = root_directory_path + "/"
									+ upload_directory_path;

		struct stat info = {};

		if (stat(full_path.c_str(), &info))
			throw std::runtime_error(
				"Upload directory does not exist: " + full_path
			);

		if (!(info.st_mode & S_IFDIR))
			throw std::runtime_error(
				"Upload path is not a directory: " + full_path
			);

		if (access(full_path.c_str(), W_OK))
			throw std::runtime_error(
				"Upload directory is not writeable: " + full_path
			);

		current_url_route->set_upload_directory(upload_directory_path);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing upload directory: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_cgi_handler(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"CGI handler must be defined within a location block"
			);

		size_t cgi_start = line.find("cgi_handler");

		if (cgi_start == std::string::npos)
			throw std::runtime_error(
				"CGI handler keyword not found"
			);
			
		cgi_start += sizeof("cgi_handler") - 1;

		if (cgi_start >= line.length())
			throw std::runtime_error(
				"Invalid CGI handler format"
			);

		const std::string content = line.substr(cgi_start);

		if (content.empty())
			throw std::runtime_error(
				"CGI handler content is empty"
			);

		std::istringstream content_stream(content);

		std::string extension;
		std::string executable;

		if (!(content_stream >> extension >> executable))
			throw std::runtime_error(
				"Invalid CGI handler format"
			);

		if (executable.back() == ';')
			executable.pop_back();

		else
		{
			size_t semicolon_pos = line.find(';');

			if (semicolon_pos == std::string::npos)
				throw std::runtime_error(
					"Invalid CGI handler format: Missing semicolon"
				);
		}

		if (extension.empty() || executable.empty())
			throw std::runtime_error(
				"CGI handler extension or executable is empty"
			);

		if (extension[0] != '.')
			extension = "." + extension;

		current_url_route->add_cgi_handler(extension, executable);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing CGI handler: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_redirect(const std::string& line) const
{
	try
	{
		if (line.empty())
			throw std::runtime_error(
				"Invalid argument provided."
			);

		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Redirect must be defined within a location block"
			);

		size_t redirect_start = line.find("redirect");

		if (redirect_start == std::string::npos)
			throw std::runtime_error(
				"Redirect keyword not found"
			);
			
		redirect_start += sizeof("redirect") - 1;

		if (redirect_start >= line.length())
			throw std::runtime_error(
				"Invalid redirect format"
			);

		size_t semicolon_pos = line.find(';', redirect_start);

		if (semicolon_pos == std::string::npos)
			throw std::runtime_error(
				"Invalid redirect format: Missing semicolon"
			);
			
		std::string redirect_url = line.substr(
			redirect_start, semicolon_pos - redirect_start
		);

		size_t first_not_space = redirect_url.find_first_not_of(" \t");

		if (first_not_space == std::string::npos)
			throw std::runtime_error(
				"Redirect URL contains only whitespace"
			);
			
		redirect_url = redirect_url.substr(first_not_space);
		
		size_t last_not_space = redirect_url.find_last_not_of(" \t");

		if (last_not_space == std::string::npos)
			throw std::runtime_error(
				"Redirect URL contains only whitespace"
			);
			
		redirect_url = redirect_url.substr(0, last_not_space + 1);

		if (redirect_url.empty())
			throw std::runtime_error(
				"Redirect URL is missing or empty"
			);

		current_url_route->set_redirect_url(redirect_url);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing redirect: "
			+ std::string(e.what())
		);
	}
}

void Parse::parse_line(const std::string& line) const
{
	if (line.empty() || line.find_first_not_of(" \t") == std::string::npos)
		return;

	/* Yes */
	static const
	std::unordered_map
	<
	std::string,
	void (Parse::*)(const std::string&) const
	>
	parsers =
	{
		{"listen",					&Parse::parse_server_listening_port	},
		{"server_name",				&Parse::parse_server_name			},
		{"root",					&Parse::parse_root_directory		},
		{"max_post_request_size",	&Parse::parse_max_post_request_size	},
		{"client_max_body_size",	&Parse::parse_client_body_size		},
		{"index",					&Parse::parse_index_file			},
		{"error_page",				&Parse::parse_error_page			},
		{"allowed_methods",			&Parse::parse_allowed_http_methods	},
		{"directory_listing",		&Parse::parse_directory_listing		},
		{"redirect",				&Parse::parse_redirect				},
		{"upload_directory",		&Parse::parse_upload_directory		},
		{"cgi_handler",				&Parse::parse_cgi_handler			}
	};

	std::istringstream	iss(line);
	std::string			cmd;

	if (!(iss >> cmd) || cmd.empty())
		return;

	auto it = parsers.find(cmd);
	if (it != parsers.end())
		(this->*(it->second))(line);
}

void Parse::validate_configuration() const
{
	if (!server_configuration->is_valid())
		throw std::runtime_error(
			"Invalid server configuration"
		);
}
