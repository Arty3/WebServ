#include <iostream>
#include <algorithm>

#include "http/HttpRequest.hpp"

HttpRequest::HttpRequest()
	:	http_request_method(HttpMethod::UNKNOWN),
		is_http_request_complete(false),
		are_http_headers_complete(false),
		is_http_request_multipart(false),
		http_request_body_start_index(0)
{
	http_request_url.clear();
	http_request_version.clear();
	http_request_headers.clear();
	http_request_body.clear();
	raw_http_request_data.clear();
	http_request_boundary.clear();
}

void HttpRequest::parse_http_request_multipart_header(const std::string& http_request_content_type)
{
	const size_t http_request_boundary_position = http_request_content_type.find("boundary=");

	if (http_request_boundary_position != std::string::npos)
	{
		http_request_boundary = http_request_content_type.substr(
			http_request_boundary_position + std::string("boundary=").length()
		);

		is_http_request_multipart = true;
	}
}

bool HttpRequest::process_incoming_http_request(const std::string& data)
{
	raw_http_request_data += data;

	if (!are_http_headers_complete)
	{
		const size_t http_request_header_end = raw_http_request_data.find("\r\n\r\n");

		if (http_request_header_end == std::string::npos)
			return false;

		const size_t first_line_end = raw_http_request_data.find("\r\n");

		if (first_line_end == std::string::npos)
			return false;

		parse_http_request_line(raw_http_request_data.substr(0, first_line_end));

		const std::string http_request_header_string = raw_http_request_data.substr(
			first_line_end + 2, http_request_header_end - (first_line_end + 2)
		);

		std::istringstream http_request_header_stream(http_request_header_string);
		parse_http_request_headers(http_request_header_stream);

		are_http_headers_complete = true;

		const auto content_type_iterator = http_request_headers.find("content-type");

		if (content_type_iterator != http_request_headers.end() &&
			content_type_iterator->second.find("multipart/form-data") != std::string::npos)
			parse_http_request_multipart_header(content_type_iterator->second);

		http_request_body_start_index = http_request_header_end + std::string("\r\n\r\n").length();

		if (http_request_method == HttpMethod::GET || (
			http_request_method == HttpMethod::POST &&
			!has_http_request_header("content-length") &&
			!is_http_request_multipart))
		{
			is_http_request_complete = true;
			return true;
		}
	}

	if (has_http_request_header("content-length"))
	{
		const size_t http_request_expected_length = std::stoull(
			get_http_request_header("content-length")
		);

		if (raw_http_request_data.length() - http_request_body_start_index >= http_request_expected_length)
		{
			http_request_body = raw_http_request_data.substr(http_request_body_start_index);
			is_http_request_complete = true;

			return true;
		}
	}
	else if (is_http_request_multipart)
	{
		const std::string http_request_boundary_end = "--" + http_request_boundary + "--\r\n";

		if (raw_http_request_data.find(http_request_boundary_end) != std::string::npos)
		{
			http_request_body = raw_http_request_data.substr(http_request_body_start_index);
			is_http_request_complete = true;

			return true;
		}
	}
	else if (http_request_method != HttpMethod::POST)
	{
		is_http_request_complete = true;
		return true;
	}

	return false;
}

void HttpRequest::parse_http_request_line(const std::string& line)
{
	std::istringstream line_stream(line);
	std::string http_request_method_string;

	if (!(line_stream >> http_request_method_string >> http_request_url >> http_request_version))
		throw std::runtime_error(
			"Invalid HTTP request line"
		);

	static const
	std::unordered_map<std::string, HttpMethod>
	method_map =
	{
		{"GET",		HttpMethod::GET		},
		{"POST",	HttpMethod::POST	},
		{"DELETE",	HttpMethod::DELETE	}
	};

	auto it = method_map.find(http_request_method_string);
	http_request_method = it != method_map.end()
						? it->second : HttpMethod::UNKNOWN;

	if (http_request_version != "HTTP/1.1" && http_request_version != "HTTP/1.0")
		throw std::runtime_error(
			"Unsupported HTTP version. Supported versions are: HTTP/1.0 and HTTP/1.1."
		);
}

void HttpRequest::parse_http_request_headers(std::istringstream& http_request_stream)
{
	std::string line;

	while (std::getline(http_request_stream, line))
	{
		if (!line.empty() && line.back() == '\r')
			line.pop_back();

		if (line.empty())
			return;

		const size_t colon_position = line.find(':');

		if (colon_position != std::string::npos)
		{
			std::string key		= line.substr(0, colon_position);
			std::string value	= line.substr(colon_position + 1);

			value.erase(0, value.find_first_not_of(" "));
			value.erase(value.find_last_not_of(" \t\r\n") + 1);

			std::transform(
				key.begin(), key.end(), key.begin(),
				static_cast<int(*)(int)>(std::tolower)
			);

			http_request_headers[key] = value;
		}
	}
}

std::string HttpRequest::get_http_request_header(const std::string& key) const
{
	std::string lower_key = key;

	std::transform(
		lower_key.begin(), lower_key.end(), lower_key.begin(),
		static_cast<int(*)(int)>(std::tolower)
	);

	const auto iterator = http_request_headers.find(lower_key);
	return iterator != http_request_headers.end() ? iterator->second : "";
}

bool HttpRequest::has_http_request_header(const std::string& key) const
{
	std::string lower_key = key;

	std::transform(
		lower_key.begin(), lower_key.end(), lower_key.begin(),
		static_cast<int(*)(int)>(std::tolower)
	);

	return http_request_headers.find(lower_key) != http_request_headers.end();
}
