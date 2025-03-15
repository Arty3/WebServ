#include "configuration/Route.hpp"

Route::Route(const std::string& file_path)
	:	url_path(file_path),
		file_system_root("./"),
		redirect_url(""),
		index_file("index.html"),
		upload_directory("./upload"),
		directory_listing(false),
		server_listening_port(0)
{
	allowed_http_methods.insert(HttpMethod::GET);
}

Route::Route(
	const std::string&	file_path,
	const std::string&	upload_directory_path,
	const bool			directory_listing_enabled,
	const int			listening_port)
	:	url_path(file_path),
		file_system_root("./"),
		redirect_url(""),
		index_file("index.html"),
		upload_directory(upload_directory_path),
		directory_listing(directory_listing_enabled),
		server_listening_port(listening_port)
{
	allowed_http_methods.insert(HttpMethod::GET);
}

std::string Route::map_url_to_filesystem_path(const std::string &requested_url) const
{
	std::string clean_path = requested_url.substr(0, requested_url.find('?'));

	if (clean_path.substr(0, url_path.length()) == url_path)
	{
		std::string relative_path = clean_path.substr(url_path.length());

		if (relative_path.empty() || relative_path[0] != '/')
			relative_path = "/" + relative_path;

		return file_system_root + relative_path;
	}

	return clean_path;
}

bool Route::does_http_request_matches_a_url_route(const std::string &requested_path) const
{
	const std::string clean_path = requested_path.substr(0, requested_path.find('?'));

	if (clean_path == url_path)
		return true;

	if (url_path.back() == '/')
		return clean_path.substr(0, url_path.length()) == url_path;

	return	clean_path.substr(0, url_path.length()) == url_path && (
			clean_path.length() == url_path.length() ||
			clean_path[url_path.length()] == '/');
}
