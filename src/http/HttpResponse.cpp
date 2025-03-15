#include <ctime>
#include <sstream>

#include "http/HttpResponse.hpp"

HttpResponse::HttpResponse()
	:	http_response_status_code(
			HttpStatusCode::HTTP_200_OK
		),
		http_version("HTTP/1.1")
{
	add_default_http_response_headers();
}

HttpResponse::HttpResponse(const HttpStatusCode http_status_code)
	:	http_response_status_code(http_status_code),
		http_version("HTTP/1.1")
{
	add_default_http_response_headers();
}

void HttpResponse::add_default_http_response_headers()
{
	const std::time_t now = std::time(nullptr);

	/* It wont reach over 31 bytes, 40 to be safe.	*/
	char date_buffer[40];

	std::strftime(
		date_buffer, sizeof(date_buffer),
		"%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&now)
	);

	http_response_headers["Date"]		= date_buffer;
	http_response_headers["Server"]		= "webserv/1.0";
	http_response_headers["Connection"]	= "keep-alive";
}

std::string HttpResponse::build_http_response() const
{
	std::ostringstream http_response;

	http_response	<< http_version
					<< " "
					<< static_cast<int>(http_response_status_code)
					<< " "
					<< get_http_response_status_code_text(http_response_status_code)
					<< "\r\n";

	for (const auto& http_response_header : http_response_headers)
		http_response	<< http_response_header.first
						<< ": "
						<< http_response_header.second
						<< "\r\n";

	http_response << "\r\n";

	if (!http_response_body.empty())
		http_response << http_response_body;

	return http_response.str();
}
