#include <fcntl.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>
#include <unordered_map>

#include "configuration/Parse.hpp"
#include "utils/utils.hpp"

Parse::Parse(std::string file_path)
	:	server_configuration_file_path(std::move(file_path)),
		server_configuration(new ServerConfiguration())
{}

void Parse::parse_server_configuration_file() const
{
	const std::string server_configuration_content = \
	Utils::read_file(server_configuration_file_path);

	std::istringstream	server_configuration_stream(server_configuration_content);
	std::string			line;

	while(std::getline(server_configuration_stream, line))
		if (line.find("server") != std::string::npos)
			parse_server_block(server_configuration_stream);

	validate_configuration();
}

void Parse::parse_server_block(std::istream &file_path) const
{
	const std::streampos start_position = file_path.tellg();

	int server_listening_port = 0;

	std::string first_line;
	while (std::getline(file_path, first_line))
	{
		if (first_line.find("listen") != std::string::npos)
		{
			server_listening_port = std::stoi(
				first_line.substr(
					first_line.find_last_of(" \t") + 1
				)
			);

			break;
		}
	}

	file_path.seekg(start_position);

	std::string line;
	while (std::getline(file_path, line))
	{
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
	const size_t location_keyword_start_index = location_line.find("location");

	if (location_keyword_start_index == std::string::npos)
		throw std::runtime_error(
			"Location block missing location keyword"
		);

	const size_t location_keyword_length = sizeof("location") - 1;

	if (location_keyword_start_index > std::string::npos - location_keyword_length)
		throw std::runtime_error(
			"Invalid file file path value found, potentially causes vulnerability"
		);

	const size_t location_file_path_start_index = location_keyword_start_index
												+ location_keyword_length;

	const size_t location_file_path_end_index = location_line.find('{');

	if (location_file_path_end_index == std::string::npos)
		throw std::runtime_error(
			"Location block missing opening brace"
		);

	if (location_file_path_end_index <= location_file_path_start_index)
		throw std::runtime_error(
			"Invalid file file path value found, potentially causes vulnerability"
		);

	std::string location_file_path = location_line.substr(
		location_file_path_start_index,
		location_file_path_end_index - location_file_path_start_index
	);

	location_file_path = location_file_path.substr(
		location_file_path.find_first_not_of(" \t")
	);

	location_file_path = location_file_path.substr(
		0, location_file_path.find_last_not_of(" \t") + 1
	);

	if (location_file_path.substr(0, 2) == "./")
		location_file_path = location_file_path.substr(2);

	if (location_file_path[0] != '/')
		location_file_path = "/" + location_file_path;

	server_configuration->start_url_route(
		location_file_path, server_listening_port
	);

	std::string line;
	while (std::getline(file_path, line))
	{
		if (line.find('}') != std::string::npos)
		{
			server_configuration->end_url_route();
			break;
		}
		parse_line(line);
	}
}

void Parse::parse_server_listening_port(const std::string& line) const
{
	try
	{
		const int server_listening_port_number = std::stoi(
			line.substr(line.find_last_of(" \t") + 1)
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
		const size_t root_directory_path_start_index	= line.find("root") + 4;
		const size_t root_directory_path_end_index		= line.find(';');

		if (root_directory_path_end_index == std::string::npos)
			throw std::runtime_error(
				"Invalid root directory format: Missing semicolon"
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

		server_configuration->set_root_directory(root_directory_path);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing root directory: " + std::string(e.what())
		);
	}
}

void Parse::parse_server_name(const std::string& line) const
{
	try
	{
		std::string server_name = line.substr(
			line.find("server_name") + sizeof("server_name") - 1
		);

		server_name = server_name.substr(0, server_name.find(';'));
		server_name = server_name.substr(server_name.find_first_not_of(" \t"));
		server_name = server_name.substr(0, server_name.find_last_not_of(" \t") + 1);

		server_configuration->add_server_name(
			server_name,
			server_configuration->get_root_directory()
		);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing server name: " + std::string(e.what())
		);
	}
}

void Parse::parse_max_post_request_size(const std::string& line) const
{
	try
	{
		std::string size_string = line.substr(
			line.find("client_max_post_request_size")
			+ sizeof("client_max_post_request_size") - 1
		);

		size_string = size_string.substr(size_string.find_first_not_of(" \t"));
		size_string = size_string.substr(size_string.find_first_of("0123456789"));
		size_string = size_string.substr(0, size_string.find(';'));

		size_t multiplier = 1;

		if (size_string.back() == 'M')
			multiplier = 1024 * 1024;
		else if (size_string.back() == 'K')
			multiplier = 1024;

		if (!std::isdigit(size_string.back()))
			size_string.pop_back();

		const size_t new_size = std::stoul(size_string) * multiplier;
		server_configuration->set_max_post_request_size(new_size);
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
		std::string size_string = line.substr(
			line.find("client_max_body_size")
			+ sizeof("client_max_body_size") - 1
		);

		size_string = size_string.substr(size_string.find_first_not_of(" \t"));
		size_string = size_string.substr(size_string.find_first_of("0123456789"));
		size_string = size_string.substr(0, size_string.find(';'));

		size_t multiplier = 1;

		if (size_string.back() == 'M')
			multiplier = 1024 * 1024;
		else if (size_string.back() == 'K')
			multiplier = 1024;

		if (!std::isdigit(size_string.back()))
			size_string.pop_back();

		const size_t new_size = std::stoul(size_string) * multiplier;
		server_configuration->set_max_request_body_size(new_size);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Invalid client_max_body_size: " + std::string(e.what())
		);
	}
}

void Parse::parse_request_read_size(const std::string& line) const
{
	try
	{
		std::string size_string = line.substr(
			line.find("request_read_buffer_size")
			+ sizeof("request_read_buffer_size") - 1
		);

		if (size_string == "default")
			return;

		size_string = size_string.substr(size_string.find_first_not_of(" \t"));
		size_string = size_string.substr(size_string.find_first_of("0123456789"));
		size_string = size_string.substr(0, size_string.find(';'));

		size_t multiplier = 1;

		if (size_string.back() == 'M')
			multiplier = 1024 * 1024;
		else if (size_string.back() == 'K')
			multiplier = 1024;

		if (!std::isdigit(size_string.back()))
			size_string.pop_back();

		const size_t new_size = std::stoul(size_string) * multiplier;
		server_configuration->set_max_request_body_size(new_size);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Invalid client_max_body_size: " + std::string(e.what())
		);
	}
}

void Parse::parse_index_file(const std::string& line) const
{
	try
	{
		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Index must be defined within a location block"
			);

		std::string index_file_path = line.substr(
			line.find("index") + sizeof("index") - 1
		);

		index_file_path = index_file_path.substr(0, index_file_path.find(';'));
		index_file_path = index_file_path.substr(index_file_path.find_first_not_of(" \t"));
		index_file_path = index_file_path.substr(0, index_file_path.find_last_not_of(" \t") + 1);

		if (index_file_path.empty())
			throw std::runtime_error(
				"Index file name is missing or empty"
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
		const std::string content = line.substr(
			line.find("error_page") + sizeof("error_page") - 1
		);

		std::istringstream	content_stream(content);
		std::string			error_page_file_path;

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

		if (root_path.substr(0, 2) == "./")
			root_path = root_path.substr(2);

		if (error_page_file_path.substr(0, 2) == "./")
			error_page_file_path = error_page_file_path.substr(2);

		const std::string full_path = root_path + "/" + error_page_file_path;

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
		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Directory listing must be defined within a location block"
			);

		std::string value = line.substr(
			line.find("directory_listing")
			+ sizeof("directory_listing") - 1
		);

		value = value.substr(0, value.find(';'));
		value = value.substr(value.find_first_not_of(" \t"));

		if (value.substr(0, 2) == "on")
			current_url_route->set_directory_listing(true);
		else if (value.substr(0, 3) == "off")
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
		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Allowed HTTP methods must be defined within a location block"
			);

		std::string http_methods = line.substr(
			line.find("allowed_methods") + sizeof("allowed_methods") - 1
		);

		http_methods = http_methods.substr(0, http_methods.find(';'));

		http_methods = http_methods.substr(http_methods.find_first_not_of(" \t"));
		http_methods = http_methods.substr(0, http_methods.find_last_not_of(" \t") + 1);

		current_url_route->remove_allowed_http_method(HttpMethod::GET);
		current_url_route->remove_allowed_http_method(HttpMethod::POST);
		current_url_route->remove_allowed_http_method(HttpMethod::DELETE);

		std::istringstream http_methods_stream(http_methods);
		std::string http_method;

		while (http_methods_stream >> http_method)
		{
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
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing allowed HTTP methods: " + std::string(e.what())
		);
	}
}

void Parse::parse_upload_directory(const std::string& line) const
{
	try
	{
		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Upload directory must be defined within a location block"
			);

		const size_t upload_directory_path_start_index = line.find("upload_directory");

		if (upload_directory_path_start_index == std::string::npos)
			throw std::runtime_error(
				"Invalid upload directory format"
			);

		std::string upload_directory_path = line.substr(
			upload_directory_path_start_index + sizeof("upload_directory") - 1
		);

		upload_directory_path = upload_directory_path.substr(0, upload_directory_path.find(';'));
		upload_directory_path = upload_directory_path.substr(upload_directory_path.find_first_not_of(" \t"));
		upload_directory_path = upload_directory_path.substr(0, upload_directory_path.find_last_not_of(" \t") + 1);

		if (upload_directory_path.empty())
			throw std::runtime_error(
				"Upload directory path is missing or empty"
			);

		std::string root_directory_path = server_configuration->get_root_directory();

		if (root_directory_path.substr(0, 2) == "./")
			root_directory_path = root_directory_path.substr(2);
		if (upload_directory_path.substr(0, 2) == "./")
			upload_directory_path = upload_directory_path.substr(2);
		if (upload_directory_path.find("www/") == 0)
			upload_directory_path = upload_directory_path.substr(4);

		const std::string full_path = root_directory_path + "/" + upload_directory_path;

		struct stat info = {};

		if (stat(full_path.c_str(), &info) != 0)
			throw std::runtime_error(
				"Upload directory does not exist: " + full_path
			);

		if (!(info.st_mode & S_IFDIR))
			throw std::runtime_error(
				"Upload path is not a directory: " + full_path
			);

		if (access(full_path.c_str(), W_OK) != 0)
			throw std::runtime_error(
				"Upload directory is not writeable: " + full_path
			);

		current_url_route->set_upload_directory(upload_directory_path);
	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing upload directory: " + std::string(e.what())
		);
	}
}

void Parse::parse_cgi_handler(const std::string& line) const
{
	try
	{
		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"CGI handler must be defined within a location block"
			);

		const std::string content = line.substr(
			line.find("cgi_handler") + sizeof("cgi_handler") - 1
		);

		std::istringstream content_stream(content);

		std::string extension;
		std::string executable;

		if (!(content_stream >> extension >> executable))
			throw std::runtime_error("Invalid CGI handler format");

		if (executable.back() == ';')
			executable.pop_back();

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
			"Error parsing CGI handler: " + std::string(e.what())
		);
	}
}

void Parse::parse_redirect(const std::string& line) const
{
	try
	{
		Route* current_url_route = server_configuration->get_current_url_route();

		if (!current_url_route)
			throw std::runtime_error(
				"Redirect must be defined within a location block"
			);

		std::string redirect_url = line.substr(
			line.find("redirect") + sizeof("redirect") - 1
		);

		redirect_url = redirect_url.substr(0, redirect_url.find(';'));
		redirect_url = redirect_url.substr(redirect_url.find_first_not_of(" \t"));
		redirect_url = redirect_url.substr(0, redirect_url.find_last_not_of(" \t") + 1);

		if (redirect_url.empty())
			throw std::runtime_error(
				"Redirect URL is missing or empty"
			);

		current_url_route->set_redirect_url(redirect_url);

	}
	catch (const std::exception& e)
	{
		throw std::runtime_error(
			"Error parsing redirect: " + std::string(e.what())
		);
	}
}

void Parse::parse_line(const std::string &line) const
{
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

	iss >> cmd;

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
