#include "aws_http_client.hpp"

#include "duckdb/common/http_util.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/database.hpp"

#include <aws/core/http/HttpClient.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/http/HttpRequest.h>
#include <aws/core/http/standard/StandardHttpRequest.h>
#include <aws/core/http/standard/StandardHttpResponse.h>
// The opt-out path (aws_network_calls_via_duckdb = false) hands back the SDK's
// own transport, which differs per platform: WinHTTP on Windows, curl elsewhere.
// The SDK only installs the headers for the transport it was built with, so this
// selection has to mirror the SDK's own DefaultHttpClientFactory. Under emscripten
// neither is built, so there the setting is effectively forced on.
#ifdef __EMSCRIPTEN__
#define AWS_HTTP_SDK_FALLBACK 0
#else
#define AWS_HTTP_SDK_FALLBACK 1
#ifdef _WIN32
#include <aws/core/http/windows/WinHttpSyncHttpClient.h>
#else
#include <aws/core/http/curl/CurlHttpClient.h>
#endif
#endif

#include <sstream>

// Bridge: an aws-sdk-cpp HttpClientFactory whose HttpClient forwards every request
// to DuckDB's polymorphic HTTPUtil (HTTPUtil::Get(db)). We only ever call the base
// HTTPUtil virtual methods; the actual transport is whatever the DatabaseInstance
// has registered (httpfs curl on native, browser fetch under wasm). See
// aws_http_client.hpp for why this is the extension's HTTP path on all platforms.

namespace duckdb {

//! The setting that toggles this bridge. Default true: all AWS SDK network calls
//! go through DuckDB's HTTPUtil. Set false (native only) to fall back to the SDK's
//! own HTTP transport.
static constexpr const char *NETWORK_VIA_DUCKDB_SETTING = "aws_network_calls_via_duckdb";

namespace {

//! Read the toggle from the database's current settings. Defaults to true when the
//! option is unset or unreadable, so the bridge is on unless explicitly disabled.
bool NetworkCallsViaDuckDB(DatabaseInstance &db) {
	Value value;
	if (db.TryGetCurrentSetting(NETWORK_VIA_DUCKDB_SETTING, value) && !value.IsNull()) {
		return BooleanValue::Get(value);
	}
	return true;
}

RequestType ToDuckDBRequestType(Aws::Http::HttpMethod method) {
	switch (method) {
	case Aws::Http::HttpMethod::HTTP_GET:
		return RequestType::GET_REQUEST;
	case Aws::Http::HttpMethod::HTTP_PUT:
		return RequestType::PUT_REQUEST;
	case Aws::Http::HttpMethod::HTTP_HEAD:
		return RequestType::HEAD_REQUEST;
	case Aws::Http::HttpMethod::HTTP_DELETE:
		return RequestType::DELETE_REQUEST;
	default:
		// AWS query-protocol services (STS/RDS/Redshift/CloudFormation) issue POST
		// with a form-urlencoded body; PATCH/OPTIONS also map here as best-effort.
		return RequestType::POST_REQUEST;
	}
}

//! DuckDB's HTTPUtil::DecomposeURL requires a '/' after the authority (it does
//! url.find('/', 8) and throws "URL needs to contain a '/' after the host"
//! otherwise). The AWS SDK serializes query-protocol endpoints
//! (STS/RDS/Redshift/CloudFormation) as a bare host with an empty path, e.g.
//! "https://cloudformation.us-east-1.amazonaws.com", so add the missing '/'.
//! SigV4 canonicalizes an empty path to "/" too, so this stays consistent with
//! what was signed.
string EnsureUrlHasPath(string url) {
	auto scheme_pos = url.find("://");
	idx_t authority_start = (scheme_pos == string::npos) ? 0 : scheme_pos + 3;
	auto sep_pos = url.find_first_of("/?#", authority_start);
	if (sep_pos == string::npos) {
		// "https://host" -> "https://host/"
		return url + "/";
	}
	if (url[sep_pos] != '/') {
		// "https://host?a=b" -> "https://host/?a=b"
		url.insert(sep_pos, "/");
	}
	return url;
}

//! Read the AWS request's body stream fully into a string (for POST/PUT).
string ReadRequestBody(const std::shared_ptr<Aws::Http::HttpRequest> &request) {
	const auto &body = request->GetContentBody();
	if (!body) {
		return string();
	}
	// Rewind BEFORE reading. The SDK signs the request by hashing this same stream
	// (SigV4 payload hash), which leaves the read position at end-of-stream. Reading
	// from there yields an empty body, so the POST goes out with no form data — e.g.
	// "Action=ListStacks&Version=2010-05-15" for the query protocol — and AWS replies
	// <UnknownOperationException/> (no Action to route). Reset again afterwards so any
	// later consumer still sees the whole body.
	body->clear();
	body->seekg(0, std::ios_base::beg);
	std::stringstream ss;
	ss << body->rdbuf();
	body->clear();
	body->seekg(0, std::ios_base::beg);
	return ss.str();
}

class DuckDBAwsHttpClient : public Aws::Http::HttpClient {
public:
	explicit DuckDBAwsHttpClient(DatabaseInstance &db_p) : db(db_p) {
	}

	std::shared_ptr<Aws::Http::HttpResponse>
	MakeRequest(const std::shared_ptr<Aws::Http::HttpRequest> &request,
	            Aws::Utils::RateLimits::RateLimiterInterface *,                  // read limiter unused
	            Aws::Utils::RateLimits::RateLimiterInterface *) const override { // write limiter unused
		auto aws_response = Aws::MakeShared<Aws::Http::Standard::StandardHttpResponse>("DuckDBAwsHttp", request);

		try {
			auto &http_util = HTTPUtil::Get(db);
			string url = EnsureUrlHasPath(request->GetUri().GetURIString(true).c_str());

			auto params = http_util.InitializeParameters(db, url);

			HTTPHeaders headers(db);
			for (const auto &header : request->GetHeaders()) {
				// The browser forbids scripts from setting these (Fetch "forbidden
				// header names") and sets them itself — host from the URL, content-length
				// from the body — logging "Refused to set unsafe header" otherwise. SigV4
				// signs 'host', but the browser reproduces the same value from the URL, so
				// the signature still validates. Skip them so the wasm client does not try.
				auto lower = StringUtil::Lower(header.first.c_str());
				if (lower == "host" || lower == "content-length") {
					continue;
				}
				headers.Insert(header.first.c_str(), header.second.c_str());
			}

			string path, proto_host_port;
			HTTPUtil::DecomposeURL(url, path, proto_host_port);
			auto client = http_util.InitializeClient(*params, proto_host_port);

			unique_ptr<HTTPResponse> response;
			string body_buffer; // request body storage kept alive across the call

			switch (ToDuckDBRequestType(request->GetMethod())) {
			case RequestType::GET_REQUEST: {
				GetRequestInfo info(
				    url, headers, *params, [](const HTTPResponse &) { return true; },
				    [&](const_data_ptr_t data, idx_t len) {
					    aws_response->GetResponseBody().write(const_char_ptr_cast(data), NumericCast<int64_t>(len));
					    return true;
				    });
				info.try_request = true;
				response = client->Get(info);
				break;
			}
			case RequestType::POST_REQUEST: {
				body_buffer = ReadRequestBody(request);
				PostRequestInfo info(url, headers, *params, const_data_ptr_cast(body_buffer.c_str()),
				                     body_buffer.size());
				info.try_request = true;
				response = client->Post(info);
				if (response) {
					aws_response->GetResponseBody().write(info.buffer_out.data(),
					                                      NumericCast<int64_t>(info.buffer_out.size()));
				}
				break;
			}
			case RequestType::PUT_REQUEST: {
				body_buffer = ReadRequestBody(request);
				string content_type = request->GetContentType().c_str();
				PutRequestInfo info(url, headers, *params, const_data_ptr_cast(body_buffer.c_str()), body_buffer.size(),
				                    content_type);
				info.try_request = true;
				response = client->Put(info);
				break;
			}
			case RequestType::HEAD_REQUEST: {
				HeadRequestInfo info(url, headers, *params);
				info.try_request = true;
				response = client->Head(info);
				break;
			}
			case RequestType::DELETE_REQUEST: {
				DeleteRequestInfo info(url, headers, *params);
				info.try_request = true;
				response = client->Delete(info);
				break;
			}
			default:
				break;
			}

			if (!response) {
				aws_response->SetResponseCode(Aws::Http::HttpResponseCode::REQUEST_NOT_MADE);
				return aws_response;
			}

			aws_response->SetResponseCode(static_cast<Aws::Http::HttpResponseCode>(static_cast<int>(response->status)));
			for (const auto &header : response->headers) {
				aws_response->AddHeader(header.first.c_str(), header.second.c_str());
			}
			// For non-GET requests whose body did not stream via a handler, copy it now.
			if (!response->body.empty()) {
				aws_response->GetResponseBody().write(response->body.data(),
				                                      NumericCast<int64_t>(response->body.size()));
			}
		} catch (std::exception &ex) {
			aws_response->SetResponseCode(Aws::Http::HttpResponseCode::REQUEST_NOT_MADE);
			aws_response->SetClientErrorType(Aws::Client::CoreErrors::NETWORK_CONNECTION);
			aws_response->SetClientErrorMessage(ex.what());
		}
		return aws_response;
	}

private:
	DatabaseInstance &db;
};

class DuckDBAwsHttpClientFactory : public Aws::Http::HttpClientFactory {
public:
	explicit DuckDBAwsHttpClientFactory(DatabaseInstance &db_p) : db(db_p) {
	}

	std::shared_ptr<Aws::Http::HttpClient>
	CreateHttpClient(const Aws::Client::ClientConfiguration &config) const override {
#if AWS_HTTP_SDK_FALLBACK
		// Opt-out (native only): hand back the SDK's own transport, exactly as the
		// default factory would, so behaviour matches a build without this bridge.
		if (!NetworkCallsViaDuckDB(db)) {
#ifdef _WIN32
			return Aws::MakeShared<Aws::Http::WinHttpSyncHttpClient>("DuckDBAwsHttp", config);
#else
			return Aws::MakeShared<Aws::Http::CurlHttpClient>("DuckDBAwsHttp", config);
#endif
		}
#endif
		return Aws::MakeShared<DuckDBAwsHttpClient>("DuckDBAwsHttp", db);
	}

	std::shared_ptr<Aws::Http::HttpRequest>
	CreateHttpRequest(const Aws::String &uri, Aws::Http::HttpMethod method,
	                  const Aws::IOStreamFactory &streamFactory) const override {
		return CreateHttpRequest(Aws::Http::URI(uri), method, streamFactory);
	}

	std::shared_ptr<Aws::Http::HttpRequest>
	CreateHttpRequest(const Aws::Http::URI &uri, Aws::Http::HttpMethod method,
	                  const Aws::IOStreamFactory &streamFactory) const override {
		auto request = Aws::MakeShared<Aws::Http::Standard::StandardHttpRequest>("DuckDBAwsHttp", uri, method);
		request->SetResponseStreamFactory(streamFactory);
		return request;
	}

private:
	DatabaseInstance &db;
};

} // namespace

void RegisterDuckDBAwsHttpClientFactory(DatabaseInstance &db) {
	Aws::Http::SetHttpClientFactory(Aws::MakeShared<DuckDBAwsHttpClientFactory>("DuckDBAwsHttp", db));
}

} // namespace duckdb
