#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <limits.h>
#include <algorithm>
#include <sys/wait.h>
#include <sys/stat.h>

#include "cgi/CGIHandler.hpp"

CGIHandler::CGIHandler(const std::string& script, const std::string& exec)
						: script_path(script), cgi_executable(exec)
{
	const size_t last_slash = script_path.find_last_of('/');

	if (last_slash != std::string::npos)
		script_directory = script_path.substr(0, last_slash);
}

bool CGIHandler::is_cgi_file(const std::string& filename)
{
	const size_t dot_position = filename.find_last_of('.');

	if (dot_position >= std::string::npos)
		return (false);

	const std::string extension = filename.substr(dot_position);
	return extension == ".php" || extension == ".py" || extension == ".pl";
}

void CGIHandler::setup_environment(const HttpRequest& request) const
{
	const std::string& url			= request.get_http_request_url();
	const size_t query_position		= url.find('?');

	const std::string query_string	= (query_position != std::string::npos) 
									? url.substr(query_position + 1) : "";

	const std::string path_info		= (query_position != std::string::npos) 
									? url.substr(0, query_position) : url;

	char absolute_path[PATH_MAX];

	if (realpath(script_path.c_str(), absolute_path) == nullptr)
		throw std::runtime_error("Failed to resolve real path for script");

	const std::string absolute_script_path(absolute_path);

	environment.clear();

	environment["GATEWAY_INTERFACE"]	= "CGI/1.1";
	environment["SERVER_PROTOCOL"]		= request.get_http_request_version();
	environment["REDIRECT_STATUS"]		= "200";
	environment["REQUEST_METHOD"]		= request.get_http_request_method() == HttpMethod::GET
										? "GET" : "POST";
	environment["PATH_INFO"]			= path_info;
	environment["PATH_TRANSLATED"]		= absolute_script_path;
	environment["SCRIPT_NAME"]			= absolute_script_path;
	environment["SCRIPT_FILENAME"]		= absolute_script_path;
	environment["QUERY_STRING"]			= query_string;
	environment["REQUEST_URI"]			= url;

	if (request.get_http_request_method() == HttpMethod::POST)
	{
		environment["CONTENT_LENGTH"]	= request.get_http_request_header("Content-Length");
		environment["CONTENT_TYPE"]		= request.get_http_request_header("Content-Type");
	}

	for (const auto& header : request.get_http_request_headers())
	{
		std::string header_name = "HTTP_" + header.first;

		std::transform(
			header_name.begin(), header_name.end(), header_name.begin(),
			static_cast<int(*)(int)>(std::toupper)
		);

		std::replace(header_name.begin(), header_name.end(), '-', '_');

		environment[header_name] = header.second;
	}

	if (environment["REQUEST_METHOD"].empty())
		environment["REQUEST_METHOD"] = "GET";

	if (environment["QUERY_STRING"].empty())
		environment["QUERY_STRING"] = "";

	std::cerr << "=== CGI Environment Variables ===\n";
	for (const auto& env : environment)
		std::cerr << env.first << "=" << env.second << "\n";
	std::cerr << "==================================\n";
}

std::string CGIHandler::unchunk_request_body(const std::string& chunked_body) const
{
	std::istringstream stream(chunked_body);

	std::string result;
	std::string line;

	size_t chunk_size;

	while (std::getline(stream, line))
	{
		if (!line.empty() && line[line.length() - 1] == '\r')
			line = line.substr(0, line.length() - 1);

		std::istringstream(line) >> std::hex >> chunk_size;

		if (!chunk_size)
			break;

		/* Note heap usage */
		char* chunk = new char[chunk_size];

		stream.read(chunk, static_cast<std::streamsize>(chunk_size));
		result.append(chunk, chunk_size);

		delete[] chunk;

		stream.ignore(2);
	}

	return result;
}

bool CGIHandler::file_exists(const std::string &file_path) const
{
	struct stat file_status = {};
	return !stat(file_path.c_str(), &file_status);
}

std::string CGIHandler::execute_cgi_script(const std::string& request_body) const
{
	int input_pipe[2];
	int output_pipe[2];

	if (pipe(input_pipe) < 0 || pipe(output_pipe) < 0)
		throw std::runtime_error(
			"Failed to create pipes"
		);

	const pid_t pid = fork();

	if (pid < 0)
		throw std::runtime_error(
			"Fork failed"
		);

	if (!pid)
	{
		close(input_pipe[1]);
		close(output_pipe[0]);

		dup2(input_pipe[0],		STDIN_FILENO);
		dup2(output_pipe[1],	STDOUT_FILENO);

		char absolute_path[PATH_MAX];

		if (realpath(script_path.c_str(), absolute_path) == nullptr)
			exit(1);

		std::string absolute_script_path(absolute_path);

		if (chdir(script_directory.c_str()) != 0)				exit(1);
		if (!file_exists(absolute_script_path))					exit(1);
		if (!file_exists(cgi_executable))						exit(1);
		if (access(absolute_script_path.c_str(), X_OK) != 0)	exit(1);
		if (access(cgi_executable.c_str(), X_OK) != 0)			exit(1);

		for (const auto& env : environment)
			std::cerr << env.first << "=" << env.second << "\n";

		for (const auto& env : environment)
			setenv(env.first.c_str(), env.second.c_str(), 1);

		execl(
			cgi_executable.c_str(),
			cgi_executable.c_str(),
			absolute_script_path.c_str(),
			NULL
		);

		exit(1);
	}

	close(input_pipe[0]);
	close(output_pipe[1]);

	if (!request_body.empty())
	{
		const ssize_t bytes_written = write(
			input_pipe[1],
			request_body.c_str(),
			request_body.length()
		);

		if (bytes_written < 0 || static_cast<size_t>(bytes_written) != request_body.length())
			throw std::runtime_error("Failed to write request body to CGI script");
	}

	close(input_pipe[1]);

	std::string	output;

	/* Read 1 page of bytes at a time */
	char	buffer[4096];
	ssize_t	bytes_read;

	while ((bytes_read = read(output_pipe[0], buffer, sizeof(buffer))) > 0)
		output.append(buffer, static_cast<size_t>(bytes_read));

	close(output_pipe[0]);

	int status;
	waitpid(pid, &status, 0);

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
	{
		std::cerr << "CGI script exited with status: "	<< WEXITSTATUS(status)
				  << ", Script: "						<< script_path
				  << ", Executable: "					<< cgi_executable
				  << std::endl;

		throw std::runtime_error(
			"CGI script execution failed"
		);
	}

	return (output);
}

void CGIHandler::handle_request(const HttpRequest& request, HttpResponse& response) const
{
	try
	{
		setup_environment(request);

		std::string request_body = "";

		if (request.get_http_request_method() == HttpMethod::POST)
		{
			request_body = request.get_http_request_body();

			if (request.get_http_request_header("Transfer-Encoding") == "chunked")
				request_body = unchunk_request_body(request_body);
		}

		const std::string	cgi_output = execute_cgi_script(request_body);
		const size_t		header_end = cgi_output.find("\r\n\r\n");

		if (header_end == std::string::npos)
		{
			response.set_http_response_content_type("text/html");
			response.set_http_response_body(cgi_output);
		}
		else
		{
			const std::string headers	= cgi_output.substr(0, header_end);
			const std::string body		= cgi_output.substr(header_end + 4);

			std::istringstream	header_stream(headers);
			std::string			header_line;

			while (std::getline(header_stream, header_line))
			{
				if (header_line.empty() || header_line == "\r")
					continue;

				const size_t colon_pos = header_line.find(": ");

				if (colon_pos != std::string::npos)
				{
					std::string key		= header_line.substr(0, colon_pos);
					std::string value	= header_line.substr(colon_pos + 2);

					if (value.back() == '\r')
						value.pop_back();

					response.set_http_response_header(key, value);
				}
			}

			response.set_http_response_body(body);
		}

		response.set_http_response_status_code(HttpStatusCode::HTTP_200_OK);
	}
	catch (const std::exception& e)
	{
		std::cerr
			<< "ERROR INFO: CGI execution failed: "
			<< e.what()
			<< "\n";

		response.set_http_response_status_code(HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR);
		response.set_http_response_body("CGI execution failed: " + std::string(e.what()));
	}
}
