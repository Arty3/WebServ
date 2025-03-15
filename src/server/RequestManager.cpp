#include <fstream>
#include <sstream>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <iostream>
#include <sys/stat.h>
#include <filesystem>

#include "cgi/CGIHandler.hpp"
#include "server/RequestManager.hpp"

RequestManager::RequestManager(
	const ServerConfiguration* server_configuration
)	: configuration(server_configuration) {}

std::string RequestManager::resolve_url_path(const std::string &url) const
{
	const std::string clean_url = url.substr(0, url.find('?'));
	std::string full_file_path = configuration->get_root_directory() + clean_url;

	if (full_file_path.find("..") != std::string::npos)
		throw std::runtime_error(
			"Attempt to access restricted files"
		);

	return full_file_path;
}

bool RequestManager::is_directory(const std::string &directory_path) const
{
	struct stat directory_status = {};

	if (stat(directory_path.c_str(), &directory_status))
		return false;

	return S_ISDIR((directory_status.st_mode));
}

bool RequestManager::file_exists(const std::string &file_path) const
{
	struct stat file_status = {};
	return (!stat(file_path.c_str(), &file_status));
}

std::string RequestManager::url_decode(const std::string& encoded) const
{
	std::string decoded;

	for (size_t i = 0; i < encoded.length(); ++i)
	{
		if (encoded[i] == '%' && i + 2 < encoded.length())
		{
			std::string hex_str = encoded.substr(i + 1, 2);

			const char decoded_char = static_cast<char>(
				std::stoi(hex_str, nullptr, 16)
			);

			decoded	+= decoded_char;
			i		+= 2;
		}
		else if (encoded[i] == '+')
			decoded += ' ';
		else
			decoded += encoded[i];
	}

	return (decoded);
}

std::string RequestManager::get_http_request_content_type(const std::string &file_path) const
{
	static const
	std::unordered_map<std::string, std::string>
	mime_types =
	{
		{"txt",		"txt"				},
		{"html",	"text/html"			},
		{"htm",		"text/html"			},
		{"css",		"text/css"			},
		{"jpg",		"image/jpeg"		},
		{"jpeg",	"image/jpeg"		},
		{"gif",		"image/gif"			},
		{"pdf",		"application/pdf"	}
	};

	size_t dot_position = file_path.find_last_of('.');
	if (dot_position == std::string::npos)
		return "application/octet-stream";

	std::string file_extension = file_path.substr(dot_position + 1);

	auto it = mime_types.find(file_extension);
	if (it != mime_types.end())
		return it->second;
	
	return "application/octet-stream";
}

std::string RequestManager::get_directory_listing(
	const std::string &directory_path,
	const std::string &url
) const
{
	std::stringstream directory_listing_html_page;

	/* Determine buffer size at compile time since macro is known */
	constexpr size_t buffer_size = sizeof(DIRECTORY_LISTING_HEADER)
								 + (_MAX_PAGE_BUF_SIZE * 2) - (2 * 2);

	char* buffer = static_cast<char*>(__builtin_alloca(buffer_size));

	std::snprintf(
		buffer, buffer_size,
		DIRECTORY_LISTING_HEADER,
		url.c_str(), url.c_str()
	);

	directory_listing_html_page << buffer;

	DIR* directory = opendir(directory_path.c_str());

	if (!directory)
	{
		try
		{
			if (std::filesystem::create_directories(directory_path))
				directory = opendir(directory_path.c_str());
		}
		catch (const std::filesystem::filesystem_error& e)
		{
			std::cerr	<< "ERROR: Failed to create directory: "
						<< e.what() << "\n";
		}

		if (!directory)
			throw std::runtime_error(
				"Failed to open or create directory: " + directory_path
			);
	}

	dirent* directory_entry;

	while ((directory_entry = readdir(directory)))
	{
		std::string name = directory_entry->d_name;

		if (name == "." || name == "..")
			continue;

		std::string full_path = directory_path + "/" + name;

		struct stat file_stat;

		if (!stat(full_path.c_str(), &file_stat))
		{
			std::string display_name = name;

			const bool isdir = static_cast<bool>(S_ISDIR(file_stat.st_mode));

			if (isdir) display_name += "/";

			std::string size = isdir ? "-"
				: std::to_string(file_stat.st_size) + " bytes";

			/* Enough for largest date string */
			char time_str[25];

			std::strftime(
				time_str,
				sizeof(time_str),
				"%Y-%m-%d %H:%M:%S",
				localtime(&file_stat.st_mtime)
			);

			/* Determine buffer size at compile time since macro is known */
			constexpr size_t buffer2_size = sizeof(DIRECTORY_LISTING_ROW)
										  + (_MAX_PAGE_BUF_SIZE * 5) - (2 * 5);

			char* buffer2 = static_cast<char*>(__builtin_alloca(buffer2_size));

			std::snprintf(
				buffer2,
				buffer2_size,
				DIRECTORY_LISTING_ROW,
				url.c_str(),
				name.c_str(),
				display_name.c_str(),
				size.c_str(),
				time_str
			);

			directory_listing_html_page << buffer2;
		}
	}

	closedir(directory);

	directory_listing_html_page << DIRECTORY_LISTING_FOOTER;
	return directory_listing_html_page.str();
}

std::string RequestManager::handle_directory_listing(
	const Route*		url_route,
	const std::string&	directory_path,
	const std::string&	url,
	HttpResponse&		http_response) const
{
	if (!url_route->is_directory_listing_enabled())
	{
		if (!url_route->get_index_file().empty())
		{
			const std::string index_path = directory_path + "/"
										 + url_route->get_index_file();

			if (file_exists(index_path))
				return index_path;
		}

		if (file_exists(directory_path + "/index.html"))
			return directory_path + "/index.html";

		std::cerr
			<< "ERROR INFO: No index file found and directory listing is disabled for: "
			<< directory_path
			<< "\n";

		serve_error_page(
			http_response,
			HttpStatusCode::HTTP_403_FORBIDDEN
		);

		return "";
	}

	if (!file_exists(directory_path))
	{
		try
		{
			std::cout	<< "INFO: Creating directory: "
						<< directory_path
						<< "\n";

			std::filesystem::create_directories(directory_path);
		}
		catch (const std::exception& e)
		{
			std::cerr	<< "ERROR: Failed to create directory: "
						<< e.what()
						<< "\n";

			serve_error_page(
				http_response,
				HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
			);

			return "";
		}
	}

	if (!url_route->get_index_file().empty())
	{
		const std::string index_path = directory_path + "/"
									 + url_route->get_index_file();

		if (file_exists(index_path))
			return index_path;
	}

	if (file_exists(directory_path + "/index.html"))
		return directory_path + "/index.html";

	try
	{
		http_response.set_http_response_content_type("text/html");
		http_response.set_http_response_body(get_directory_listing(directory_path, url));
		http_response.set_http_response_status_code(HttpStatusCode::HTTP_200_OK);

		return "";
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR: Failed to create directory listing: "
			<< e.what()
			<< "\n";

		serve_error_page(
			http_response,
			HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
		);

		return "";
	}
}

void RequestManager::handle_http_get_request(
	const std::string&	url,
	const HttpRequest&	request,
	HttpResponse&		http_response,
	const int			server_listening_port) const
{
	try
	{
		const std::string	decoded_url = url_decode(url);
		const Route*		url_route	= configuration->find_url_route_for_listening_port(
											server_listening_port, decoded_url);

		if (!url_route)
		{
			std::cerr
				<< "ERROR INFO: No route found for URL: "
				<< url
				<< " on port: "
				<< server_listening_port
				<< "\n";

			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_403_FORBIDDEN
			);

			return;
		}

		if (url_route->should_redirect())
		{
			const std::string redirect_url = url_route->get_redirect_url();

			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_301_MOVED_PERMANENTLY
			);

			http_response.set_http_response_header(
				"Location", redirect_url
			);

			std::cerr
				<< "INFO: Redirecting from "
				<< url
				<< " to "
				<< redirect_url
				<< "\n";

			return;
		}

		const std::string	url_route_root_directory	= url_route->get_filesystem_root();
		std::string			directory_path				= url_route_root_directory + decoded_url;

		if (handle_cgi_request(url_route, directory_path, request, http_response)) return;

		if (is_directory(directory_path))
		{
			const std::string resolved_path = handle_directory_listing(
				url_route, directory_path, url, http_response
			);

			if (resolved_path.empty())
				return;

			directory_path = resolved_path;
		}

		if (!file_exists(directory_path))
		{
			std::cerr
				<< "ERROR INFO: File does not exist: "
				<< directory_path
				<< "\n";

			serve_error_page(
				http_response,
				HttpStatusCode::HTTP_404_NOT_FOUND
			);

			return;
		}

		http_response.set_http_response_content_type(get_http_request_content_type(directory_path));
		http_response.set_http_response_body(get_file_content(directory_path));
		http_response.set_http_response_status_code(HttpStatusCode::HTTP_200_OK);
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: Error while handling HTTP GET request for URL: "
			<< url
			<< ", error: "
			<< e.what()
			<< "\n";

		serve_error_page(
			http_response,
			HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
		);
	}
}

void RequestManager::handle_http_post_request(
	const std::string&	url,
	const HttpRequest&	http_request,
	HttpResponse&		http_response,
	const int			server_listening_port) const
{
	try
	{
		if (http_request.has_http_request_header("content-length"))
		{
			const size_t http_post_request_expected_length = std::stoull(
				http_request.get_http_request_header("content-length")
			);

			if (http_post_request_expected_length > configuration->get_max_post_request_size())
			{
				std::cerr
					<< "ERROR INFO: Content-Length ("
					<< http_post_request_expected_length
					<< ") exceeds allowed limit.\n";

				http_response.set_http_response_status_code(
					HttpStatusCode::HTTP_413_PAYLOAD_TOO_LARGE
				);

				http_response.set_http_response_content_type("text/html");
				http_response.set_http_response_body(HTTP_PAGE_413_PAYLOAD_TOO_LARGE);

				return;
			}
		}

		const Route* url_route = configuration->find_url_route_for_listening_port(server_listening_port, url);

		if (!url_route || !url_route->is_http_method_allowed(HttpMethod::POST))
		{
			std::cerr
				<< "ERROR INFO: POST method is not allowed for URL: "
				<< url
				<< "\n";

			http_response.set_http_response_status_code(HttpStatusCode::HTTP_405_METHOD_NOT_ALLOWED);
			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(HTTP_PAGE_405_METHOD_NOT_ALLOWED);

			return;
		}

		std::string upload_directory = url_route->get_filesystem_root() + "/"
									 + url_route->get_upload_directory();

		if (upload_directory.substr(0, 2) == "./")
			upload_directory = upload_directory.substr(2);

		std::string filename;
		std::string http_post_request_processed_body;

		if (!http_request.has_http_request_header("content-length") ||
			http_request.get_http_request_header("content-length") == "0")
			filename = "empty_post_" + std::to_string(std::time(nullptr)) + ".txt";

		else if (http_request.get_http_request_header("Content-Type")
					.find("multipart/form-data") != std::string::npos &&
				!http_request.get_http_request_boundary().empty())
		{
			http_post_request_processed_body = remove_http_request_boundary(
				http_request.get_http_request_body(),
				http_request.get_http_request_boundary()
			);

			size_t filename_start_index = http_request.get_http_request_body().find("filename=\"");
			if (filename_start_index != std::string::npos)
			{
				filename_start_index += std::string("filename=\"").length();

				const size_t filename_end_index = http_request.get_http_request_body()
													.find("\"", filename_start_index);

				if (filename_end_index != std::string::npos)
					filename = http_request.get_http_request_body().substr(
						filename_start_index, filename_end_index - filename_start_index
					);
			}
		}
		else
		{
			filename = "post_" + std::to_string(std::time(nullptr)) + ".txt";
			http_post_request_processed_body = http_request.get_http_request_body();
		}

		if (filename.empty())
			filename = "unnamed_" + std::to_string(std::time(nullptr)) + ".txt";

		const std::string filepath = upload_directory + "/" + filename;

		const int file_descriptor = open(
			filepath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644
		);

		if (file_descriptor < 0)
		{
			std::cerr
				<< "ERROR INFO: Failed to open file for writing: "
				<< filepath
				<< "\n";

			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
			);

			return;
		}

		int flags = fcntl(file_descriptor, F_GETFL, 0);
		fcntl(file_descriptor, F_SETFL, flags | O_NONBLOCK);

		ssize_t bytes_written = 0;

		if (!http_post_request_processed_body.empty())
		{
			bytes_written = write(file_descriptor,
				http_post_request_processed_body.c_str(),
				http_post_request_processed_body.length()
			);

			if (bytes_written < 0)
			{
				std::cerr
					<< "ERROR INFO: Failed to write to file: " 
					<< filepath 
					<< "\n";

				close(file_descriptor);

				http_response.set_http_response_status_code(
					HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
				);

				return;
			}
		}

		close(file_descriptor);

		http_response.set_http_response_status_code(HttpStatusCode::HTTP_201_CREATED);
		http_response.set_http_response_content_type("text/html");
		http_response.set_http_response_body(HTTP_PAGE_201_CREATED);
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: Error while handling HTTP POST request for URL: "
			<< url
			<< ", error: "
			<< e.what()
			<< "\n";

		http_response.set_http_response_status_code(
			HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
		);
	}
}

void RequestManager::handle_http_delete_request(
	const std::string&	url,
	HttpResponse&		http_response,
	const int			server_listening_port) const
{
	try
	{
		const Route* url_route = configuration->find_url_route_for_listening_port(
									server_listening_port, url);

		if (!url_route)
		{
			std::cerr
				<< "ERROR INFO: No URL route found for DELETE request: "
				<< url
				<< "\n";

			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_403_FORBIDDEN
			);

			return;
		}

		if (!url_route->is_http_method_allowed(HttpMethod::DELETE))
		{
			std::cerr
				<< "ERROR INFO: DELETE method not allowed for URL: "
				<< url
				<< "\n";

			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_405_METHOD_NOT_ALLOWED
			);

			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(HTTP_PAGE_405_METHOD_NOT_ALLOWED);

			return;
		}

		std::string upload_directory = url_route->get_filesystem_root() + "/"
									 + url_route->get_upload_directory();

		if (upload_directory.substr(0, 2) == "./")
			upload_directory = upload_directory.substr(2);

		const std::string encoded_filename	= url.substr(url.find_last_of('/') + 1);
		const std::string filename			= url_decode(encoded_filename);

		if (filename.empty())
		{
			std::cerr
				<< "ERROR INFO: Empty filename in DELETE request for URL: "
				<< url
				<< "\n";

			http_response.set_http_response_status_code(HttpStatusCode::HTTP_400_BAD_REQUEST);
			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(HTTP_PAGE_400_BAD_REQUEST);

			return;
		}

		const std::string filepath = upload_directory + "/" + filename;

		if (!file_exists(filepath))
		{
			std::cerr
				<< "ERROR INFO: File not found for DELETE request: "
				<< filepath
				<< "\n";

			http_response.set_http_response_status_code(HttpStatusCode::HTTP_404_NOT_FOUND);
			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(HTTP_PAGE_404_NOT_FOUND);

			return;
		}

		if (std::remove(filepath.c_str()) != 0)
		{
			std::cerr
				<< "ERROR INFO: Failed to remove file: "
				<< filepath
				<< "\n";

			http_response.set_http_response_status_code(
				HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
			);

			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(HTTP_PAGE_500_INTERNAL_SERVER_ERROR);

			return;
		}

		std::cout << "INFO: Successfully deleted file: " << filepath << "\n";
		http_response.set_http_response_status_code(HttpStatusCode::HTTP_204_NO_CONTENT);
		http_response.set_http_response_content_type("text/html");
		http_response.set_http_response_body(HTTP_PAGE_204_NO_CONTENT);
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: Error while handling HTTP DELETE request for URL: "
			<< url
			<< ", error: "
			<< e.what()
			<< "\n";

		http_response.set_http_response_status_code(HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR);
		http_response.set_http_response_content_type("text/html");
		http_response.set_http_response_body(HTTP_PAGE_500_INTERNAL_SERVER_ERROR);
	}
}

bool RequestManager::handle_cgi_request(
	const Route*		route,
	const std::string&	path,
	const HttpRequest&	request,
	HttpResponse&		response) const
{
	if (!route || path.empty())
		return false;

	std::string		script_path		= path;
	const size_t	query_position	= script_path.find('?');

	if (query_position != std::string::npos)
		script_path = script_path.substr(0, query_position);

	const size_t extension_position = script_path.find_last_of('.');

	if (extension_position == std::string::npos)
		return false;

	const std::string extension = script_path.substr(extension_position);

	if (!route->has_cgi_handler(extension))
		return false;

	try
	{
		const CGIHandler cgi_handler(
			script_path,
			route->get_cgi_handler(extension)
		);

		cgi_handler.handle_request(request, response);

		return true;
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: CGI execution failed: "
			<< e.what()
			<< " (Script: "
			<< script_path
			<< ")\n";

		serve_error_page(
			response,
			HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR
		);

		return true;
	}
}

void RequestManager::serve_error_page(
	HttpResponse&	http_response,
	HttpStatusCode	http_status_code) const
{
	try
	{
		const std::string error_page_path = configuration->get_root_directory() + '/'
										  + configuration->get_default_error_page_path();

		if (file_exists(error_page_path))
		{
			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(get_file_content(error_page_path));
		}
		else
		{
			const std::string basic_error =
			"<html><body><h1>Error "
			+ std::to_string(static_cast<int>(http_status_code))
			+ "</h1><p>"
			+ get_http_response_status_code_text(http_status_code)
			+ "</p></body></html>";

			http_response.set_http_response_content_type("text/html");
			http_response.set_http_response_body(basic_error);
		}

		http_response.set_http_response_status_code(http_status_code);
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: Exception occurred while attempting to serve the error page. "
			<< "Requested HTTP status code: "
			<< static_cast<int>(http_status_code)
			<< ", Exception details: "
			<< e.what()
			<< "\n";

		http_response.set_http_response_status_code(HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR);
		http_response.set_http_response_content_type("text/html");
		http_response.set_http_response_body(HTTP_PAGE_500_INTERNAL_SERVER_ERROR);
	}
}

std::string RequestManager::remove_http_request_boundary(
	const std::string&	http_request_body,
	const std::string&	http_request_boundary) const
{
	std::string full_boundary = "--" + http_request_boundary;
	
	size_t pos = http_request_body.find(full_boundary);

	if (pos == std::string::npos)
		throw std::runtime_error(
			"Couldn't find first request boundary"
		);
	
	pos = http_request_body.find("\r\n\r\n", pos);
	if (pos == std::string::npos)
		throw std::runtime_error(
			"Couldn't find end of request headers"
		);
	
	const size_t content_start = pos + 4;
	
	size_t content_end = http_request_body.find(full_boundary, content_start);
	if (content_end == std::string::npos)
		throw std::runtime_error(
			"Couldn't find ending request boundary"
		);
	
	if (content_end >= 2 && http_request_body.substr(content_end - 2, 2) == "\r\n")
		content_end -= 2;
	
	return http_request_body.substr(
		content_start, content_end - content_start
	);
}
