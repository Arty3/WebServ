#pragma once

#include <unordered_map>
#include <functional>

/* There's a method to the madness */

#define HTTP_PAGE_201_CREATED				"<!DOCTYPE html><html><head><title>201 - File Uploaded</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}button{background-color:#4CAF50;color:white;padding:15px 32px;border:none;text-align:center;text-decoration:none;display:inline-block;font-size:16px;margin:4px 2px;cursor:pointer;border-radius:4px;transition:background-color 0.3s ease;}button:hover{background-color:#45a049;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>File Uploaded Successfully</h1><p>Your file is now available in the server upload directory.</p><button onclick=\"window.location.href='/'\">Return to Home</button></div></body></html>"
#define HTTP_PAGE_204_NO_CONTENT			"<!DOCTYPE html><html><head><title>204 - No Content</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}a{color:#007bff;text-decoration:none;font-weight:bold;border:2px solid #007bff;padding:10px 20px;border-radius:5px;transition:all 0.3s ease;}a:hover{background-color:#007bff;color:white;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>204 - No Content</h1><p>The operation was successful, but there is no content to display.</p><p><a href=\"/\">Return to Homepage</a></p></div></body></html>"
#define HTTP_PAGE_400_BAD_REQUEST			"<!DOCTYPE html><html><head><title>400 - Bad Request</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}a{color:#007bff;text-decoration:none;font-weight:bold;border:2px solid #007bff;padding:10px 20px;border-radius:5px;transition:all 0.3s ease;}a:hover{background-color:#007bff;color:white;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>400 - Bad Request</h1><p>Your request was invalid or missing necessary parameters.</p><p>Please check your input and try again.</p><p><a href=\"/\">Return to Homepage</a></p></div></body></html>"
#define HTTP_PAGE_404_NOT_FOUND				"<!DOCTYPE html><html><head><title>404 - Not Found</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}a{color:#007bff;text-decoration:none;font-weight:bold;border:2px solid #007bff;padding:10px 20px;border-radius:5px;transition:all 0.3s ease;}a:hover{background-color:#007bff;color:white;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>404 - Not Found</h1><p>The requested resource could not be found on this server.</p><p><a href=\"/\">Return to Homepage</a></p></div></body></html>"
#define HTTP_PAGE_405_METHOD_NOT_ALLOWED	"<!DOCTYPE html><html><head><title>405 - Method Not Allowed</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}a{color:#007bff;text-decoration:none;font-weight:bold;border:2px solid #007bff;padding:10px 20px;border-radius:5px;transition:all 0.3s ease;}a:hover{background-color:#007bff;color:white;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class='container'><h1>405 - Method Not Allowed</h1><p>POST requests are not allowed on this route.</p><p><a href='/'>Return to Homepage</a></p></div></body></html>"
#define HTTP_PAGE_413_PAYLOAD_TOO_LARGE		"<!DOCTYPE html><html><head><title>413 - Payload Too Large</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}a{color:#007bff;text-decoration:none;font-weight:bold;border:2px solid #007bff;padding:10px 20px;border-radius:5px;transition:all 0.3s ease;}a:hover{background-color:#007bff;color:white;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>413 - Payload Too Large</h1><p>File too large. Maximum size is 10MB.</p><p><a href=\"/\">Return to Homepage</a></p></div></body></html>"
#define HTTP_PAGE_500_INTERNAL_SERVER_ERROR	"<!DOCTYPE html><html><head><title>500 - Internal Server Error</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:600px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}p{color:#6c757d;font-size:1.2em;margin:15px 0;}a{color:#007bff;text-decoration:none;font-weight:bold;border:2px solid #007bff;padding:10px 20px;border-radius:5px;transition:all 0.3s ease;}a:hover{background-color:#007bff;color:white;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>500 - Internal Server Error</h1><p>An unexpected error occurred on the server. Please try again later.</p><p><a href=\"/\">Return to Homepage</a></p></div></body></html>"

#define DIRECTORY_LISTING_HEADER			"<!DOCTYPE html><html><head><title>Index of %s</title><style>body{font-family:'Arial',sans-serif;text-align:center;padding:50px;background-color:#f8f9fa;color:#343a40;}.container{background-color:white;padding:50px;border-radius:12px;box-shadow:0 4px 8px rgba(0,0,0,0.1);max-width:1000px;margin:0 auto;animation:fadeIn 0.5s ease-in-out;}h1{font-size:2.5em;color:#495057;margin-bottom:20px;}table{width:100%%;border-collapse:collapse;margin:20px 0;}th,td{text-align:left;padding:12px;border-bottom:1px solid #dee2e6;}th{background-color:#f8f9fa;font-weight:600;color:#495057;}tr:hover{background-color:#f8f9fa;}a{color:#007bff;text-decoration:none;transition:color 0.2s ease;}a:hover{color:#0056b3;text-decoration:underline;}.home-button{display:inline-block;margin-top:20px;padding:10px 20px;background-color:#007bff;color:white;border-radius:5px;text-decoration:none;transition:background-color 0.3s ease;}.home-button:hover{background-color:#0056b3;color:white;text-decoration:none;}@keyframes fadeIn{from{opacity:0;transform:translateY(-10px);}to{opacity:1;transform:translateY(0);}}</style></head><body><div class=\"container\"><h1>Index of %s</h1><table><tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>"
#define DIRECTORY_LISTING_ROW				"<tr><td><a href=\"%s/%s\">%s</a></td><td>%s</td><td>%s</td></tr>"
#define DIRECTORY_LISTING_FOOTER			"</table><a href=\"/\" class=\"home-button\">Return to Homepage</a></div></body></html>"

#define _MAX_PAGE_BUF_SIZE	8192 /* 2 pages of bytes */

enum class HttpStatusCode
{
	/* 2XX Success */
	HTTP_200_OK						= 200,
	HTTP_201_CREATED				= 201,
	HTTP_202_ACCEPTED				= 202,
	HTTP_204_NO_CONTENT				= 204,

	/* 3XX Redirection */
	HTTP_301_MOVED_PERMANENTLY		= 301,
	HTTP_302_FOUND					= 302,
	HTTP_303_SEE_OTHER				= 303,
	HTTP_304_NOT_MODIFIED			= 304,
	HTTP_307_TEMPORARY_REDIRECT		= 307,
	HTTP_308_PERMANENT_REDIRECT		= 308,

	/* 4XX Client Errors */
	HTTP_400_BAD_REQUEST			= 400,
	HTTP_401_UNAUTHORIZED			= 401,
	HTTP_403_FORBIDDEN				= 403,
	HTTP_404_NOT_FOUND				= 404,
	HTTP_405_METHOD_NOT_ALLOWED		= 405,
	HTTP_408_REQUEST_TIMEOUT		= 408,
	HTTP_409_CONFLICT				= 409,
	HTTP_411_LENGTH_REQUIRED		= 411,
	HTTP_413_PAYLOAD_TOO_LARGE		= 413,
	HTTP_414_URI_TOO_LONG			= 414,
	HTTP_415_UNSUPPORTED_MEDIA_TYPE	= 415,

	/* 5XX Server Errors */
	HTTP_500_INTERNAL_SERVER_ERROR	= 500,
	HTTP_501_NOT_IMPLEMENTED		= 501,
	HTTP_502_BAD_GATEWAY			= 502,
	HTTP_503_SERVICE_UNAVAILABLE	= 503,
	HTTP_504_GATEWAY_TIMEOUT		= 504
};

/**
* @brief Implements a hashing function for the codes
*
* @param code The status code to hash
* @return The resulting hash
*/
namespace std
{
	template<>
	struct hash<HttpStatusCode>
	{
		size_t operator()(const HttpStatusCode& code) const noexcept
		{
			return static_cast<size_t>(code);
		}
	};
}

/**
* @brief Converts HTTP status code to its text message
*
* @param status The status code to convert
* @return The matching text message (like "OK" for 200)
*/
static inline const char* get_http_response_status_code_text(const HttpStatusCode status)
{
	/* Ported from switch statement for better readibility and efficiency */
	static const std::unordered_map<HttpStatusCode, const char*> status_texts = 
	{
		{HttpStatusCode::HTTP_200_OK,						"OK"},
		{HttpStatusCode::HTTP_201_CREATED,					"Created"},
		{HttpStatusCode::HTTP_202_ACCEPTED,					"Accepted"},
		{HttpStatusCode::HTTP_204_NO_CONTENT,				"No Content"},
		{HttpStatusCode::HTTP_301_MOVED_PERMANENTLY,		"Moved Permanently"},
		{HttpStatusCode::HTTP_302_FOUND,					"Found"},
		{HttpStatusCode::HTTP_303_SEE_OTHER,				"See Other"},
		{HttpStatusCode::HTTP_304_NOT_MODIFIED,				"Not Modified"},
		{HttpStatusCode::HTTP_307_TEMPORARY_REDIRECT,		"Temporary Redirect"},
		{HttpStatusCode::HTTP_308_PERMANENT_REDIRECT,		"Permanent Redirect"},
		{HttpStatusCode::HTTP_400_BAD_REQUEST,				"Bad Request"},
		{HttpStatusCode::HTTP_401_UNAUTHORIZED,				"Unauthorized"},
		{HttpStatusCode::HTTP_403_FORBIDDEN,				"Forbidden"},
		{HttpStatusCode::HTTP_404_NOT_FOUND,				"Not Found"},
		{HttpStatusCode::HTTP_405_METHOD_NOT_ALLOWED,		"Method Not Allowed"},
		{HttpStatusCode::HTTP_408_REQUEST_TIMEOUT,			"Request Timeout"},
		{HttpStatusCode::HTTP_409_CONFLICT,					"Conflict"},
		{HttpStatusCode::HTTP_411_LENGTH_REQUIRED,			"Length Required"},
		{HttpStatusCode::HTTP_413_PAYLOAD_TOO_LARGE,		"Payload Too Large"},
		{HttpStatusCode::HTTP_414_URI_TOO_LONG,				"URI Too Long"},
		{HttpStatusCode::HTTP_415_UNSUPPORTED_MEDIA_TYPE,	"Unsupported Media Type"},
		{HttpStatusCode::HTTP_500_INTERNAL_SERVER_ERROR,	"Internal Server Error"},
		{HttpStatusCode::HTTP_501_NOT_IMPLEMENTED,			"Not Implemented"},
		{HttpStatusCode::HTTP_502_BAD_GATEWAY,				"Bad Gateway"},
		{HttpStatusCode::HTTP_503_SERVICE_UNAVAILABLE,		"Service Unavailable"},
		{HttpStatusCode::HTTP_504_GATEWAY_TIMEOUT,			"Gateway Timeout"}
	};

	auto it = status_texts.find(status);
	if (it != status_texts.end())
		return it->second;

	return "Unknown Status";
}
