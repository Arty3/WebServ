#include <iostream>

#include "configuration/ServerConfiguration.hpp"

ServerConfiguration::ServerConfiguration() : current_url_route(nullptr) {}

void ServerConfiguration::start_url_route(const std::string& file_path, const int port)
{
	url_routes.push_back(Route(file_path));

	current_url_route = &url_routes.back();
	current_url_route->set_filesystem_root(root_directory);
	current_url_route->set_server_listening_port(port);
}

const Route* ServerConfiguration::find_url_route_for_listening_port(const int listening_port, const std::string& file_path) const
{
	const Route* best_url_route = nullptr;
	size_t longest_url_route_match = 0;

	for (const Route& route : url_routes)
	{
		if (route.get_server_listening_port() != listening_port)
			continue;

		if (route.does_http_request_matches_a_url_route(file_path))
		{
			const size_t length_url_route_match = route.get_url_path().length();

			if (length_url_route_match > longest_url_route_match)
			{
				longest_url_route_match = length_url_route_match;
				best_url_route = &route;
			}
		}
	}
	return best_url_route;
}

std::string ServerConfiguration::get_server_configuration_string() const
{
	/* How is it that it's 2025 and there's still no better string handling */

	std::ostringstream out;

	out << "\n=== Server Configuration ===\n";
	out << "Listening port(s): ";

	for (const auto& port : get_server_listening_ports())
		out << port << " ";

	out																			<< "\n"
		<< "Server name: "				<< get_server_names().begin()->first	<< "\n"
		<< "Root directory: "			<< get_root_directory()					<< "\n"
		<< "Max client body size: "		<< get_max_request_body_size()			<< " bytes\n"
		<< "Max post request size: "	<< get_max_post_request_size()			<< " bytes\n"
		<< "Request buffer read size: "	<< get_request_read_size()				<< " bytes\n"
		<< "Default error page: "		<< get_default_error_page_path()		<< "\n";

	out << "\n=== Route Configurations ===\n";

	for (const Route& route : url_routes)
	{
		out
			<< "\nLocation: "			<< route.get_url_path()			<< "\n"
			<< "  Root: "				<< route.get_filesystem_root()	<< "\n"
			<< "  Directory listing: "	<< (route.is_directory_listing_enabled()
										? "enabled" : "disabled")		<< "\n";

		if (!route.get_index_file().empty())
			out << "  Index file: "
							<< route.get_index_file()
							<< "\n";

		out << "  Allowed methods:";

		if (route.is_http_method_allowed(HttpMethod::GET))		out << " GET";
		if (route.is_http_method_allowed(HttpMethod::POST))		out << " POST";
		if (route.is_http_method_allowed(HttpMethod::DELETE))	out << " DELETE";

		out << "\n";

		if (!route.get_upload_directory().empty())
			out << "  Upload directory: "
							<< route.get_upload_directory()
							<< "\n";

		if (route.should_redirect())
			out << "  Redirect to: "
							<< route.get_redirect_url()
							<< "\n";
	}

	out << "\n============================\n";

	return out.str();
}
