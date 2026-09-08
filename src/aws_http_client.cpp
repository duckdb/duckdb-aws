#include "aws_http_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/http_util.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/logging/log_manager.hpp"
#include "duckdb/main/extension_helper.hpp"

#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/HttpClient.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/http/HttpRequest.h>
#include <aws/core/http/HttpTypes.h>
#include <aws/core/http/standard/StandardHttpRequest.h>
#include <aws/core/http/standard/StandardHttpResponse.h>

// The opt-out path hands back the SDK's own transport, and which one that is depends on how
// the SDK was built rather than on the host OS: a Windows SDK built with FORCE_CURL uses
// curl, and keying this on _WIN32 would leave WinHttpSyncHttpClient unresolved at link time.
// The SDK's own selection macros (ENABLE_CURL_CLIENT etc.) are not exported to consumers,
// but it installs only the headers for the transport it was compiled with, so probe for
// those. Where neither is present (emscripten) the bridge is the only path and the setting
// is ignored.
#if defined(__EMSCRIPTEN__)
#define AWS_HTTP_SDK_FALLBACK      0
#define AWS_HTTP_SDK_FALLBACK_CURL 0
#elif defined(_WIN32) && __has_include(<aws/core/http/windows/WinHttpSyncHttpClient.h>)
#define AWS_HTTP_SDK_FALLBACK      1
#define AWS_HTTP_SDK_FALLBACK_CURL 0
#include <aws/core/http/windows/WinHttpSyncHttpClient.h>
#elif __has_include(<aws/core/http/curl/CurlHttpClient.h>)
#define AWS_HTTP_SDK_FALLBACK      1
#define AWS_HTTP_SDK_FALLBACK_CURL 1
#include <aws/core/http/curl/CurlHttpClient.h>
#else
#define AWS_HTTP_SDK_FALLBACK      0
#define AWS_HTTP_SDK_FALLBACK_CURL 0
#endif

#include <atomic>
#include <sstream>

namespace duckdb {

static constexpr const char *NETWORK_VIA_DUCKDB_SETTING = "aws_network_calls_via_duckdb";

namespace {

//! Defaults to true, so the bridge is on unless explicitly disabled. Registered as a
//! GLOBAL-scoped option, since this is read off the DatabaseInstance rather than a
//! ClientContext and a session-scoped value would never be seen here.
bool NetworkCallsViaDuckDB(DatabaseInstance &db) {
	Value value;
	if (db.TryGetCurrentSetting(NETWORK_VIA_DUCKDB_SETTING, value) && !value.IsNull()) {
		return BooleanValue::Get(value);
	}
	return true;
}

#if AWS_HTTP_SDK_FALLBACK_CURL
std::atomic<bool> curl_global_initialized {false};

//! Aws::Http::SetHttpClientFactory() calls CleanupHttp(), which tears down curl's global
//! state through the default factory, and nothing ever re-initializes it: a later
//! Aws::InitAPI() finds a non-null factory and only calls our InitStaticState(). So the
//! fallback client has to bring curl back up itself before the first curl_easy_init().
void EnsureCurlGlobalState() {
	bool expected = false;
	if (curl_global_initialized.compare_exchange_strong(expected, true)) {
		Aws::Http::CurlHttpClient::InitGlobalState();
	}
}
#endif

bool TryGetRequestType(Aws::Http::HttpMethod method, RequestType &result) {
	switch (method) {
	case Aws::Http::HttpMethod::HTTP_GET:
		result = RequestType::GET_REQUEST;
		return true;
	case Aws::Http::HttpMethod::HTTP_PUT:
		result = RequestType::PUT_REQUEST;
		return true;
	case Aws::Http::HttpMethod::HTTP_HEAD:
		result = RequestType::HEAD_REQUEST;
		return true;
	case Aws::Http::HttpMethod::HTTP_DELETE:
		result = RequestType::DELETE_REQUEST;
		return true;
	case Aws::Http::HttpMethod::HTTP_POST:
		result = RequestType::POST_REQUEST;
		return true;
	case Aws::Http::HttpMethod::HTTP_OPTIONS:
		result = RequestType::OPTIONS_REQUEST;
		return true;
	default:
		// PATCH has no HTTPUtil equivalent. Refuse it rather than silently issuing it as a
		// POST, which a server would act on with different semantics.
		return false;
	}
}

//! Core HTTPUtil implements only GET; Put/Head/Delete/Post all throw NotImplemented. Every
//! AWS call this extension makes is a POST, so an httpfs-provided transport is required.
//! Auto-load it rather than surfacing an opaque "POST request not implemented".
HTTPUtil &GetTransport(DatabaseInstance &db) {
	auto &http_util = HTTPUtil::Get(db);
	if (http_util.GetName() != "Built-In") {
		return http_util;
	}
	if (ExtensionHelper::TryAutoLoadExtension(db, "httpfs")) {
		auto &loaded = HTTPUtil::Get(db);
		if (loaded.GetName() != "Built-In") {
			return loaded;
		}
	}
	throw InvalidConfigurationException(
	    "AWS network calls are routed through DuckDB's HTTP layer, which only supports GET without the httpfs "
	    "extension. Run 'INSTALL httpfs; LOAD httpfs;'"
#if AWS_HTTP_SDK_FALLBACK
	    ", or 'SET GLOBAL %s = false' to use the AWS SDK's own HTTP client",
	    NETWORK_VIA_DUCKDB_SETTING);
#else
	);
#endif
}

//! HTTPUtil::DecomposeURL throws unless a '/' follows the authority, but the SDK
//! serializes query-protocol endpoints as a bare host ("https://cloudformation.
//! us-east-1.amazonaws.com"). SigV4 canonicalizes an empty path to "/" as well, so
//! adding it keeps the URL consistent with what was signed.
string EnsureUrlHasPath(string url) {
	auto scheme_pos = url.find("://");
	idx_t authority_start = (scheme_pos == string::npos) ? 0 : scheme_pos + 3;
	auto sep_pos = url.find_first_of("/?#", authority_start);
	if (sep_pos == string::npos) {
		return url + "/";
	}
	if (url[sep_pos] != '/') {
		// "https://host?a=b" -> "https://host/?a=b"
		url.insert(sep_pos, "/");
	}
	return url;
}

string ReadRequestBody(const std::shared_ptr<Aws::Http::HttpRequest> &request) {
	const auto &body = request->GetContentBody();
	if (!body) {
		return string();
	}
	// Rewind BEFORE reading: SigV4 hashes this same stream when signing, leaving it at
	// end-of-stream. Reading from there sends an empty body and AWS answers
	// <UnknownOperationException/>. Rewind afterwards too, for any later consumer.
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
	DuckDBAwsHttpClient(weak_ptr<DatabaseInstance> db_p, const Aws::Client::ClientConfiguration &config)
	    : db(std::move(db_p)), request_timeout_ms(config.requestTimeoutMs), verify_ssl(config.verifySSL),
	      follow_redirects(config.followRedirects != Aws::Client::FollowRedirectsPolicy::NEVER),
	      proxy_host(config.proxyHost.c_str()), proxy_port(config.proxyPort),
	      proxy_username(config.proxyUserName.c_str()), proxy_password(config.proxyPassword.c_str()) {
	}

	std::shared_ptr<Aws::Http::HttpResponse>
	MakeRequest(const std::shared_ptr<Aws::Http::HttpRequest> &request,
	            Aws::Utils::RateLimits::RateLimiterInterface *,                  // read limiter unused
	            Aws::Utils::RateLimits::RateLimiterInterface *) const override { // write limiter unused
		auto aws_response = Aws::MakeShared<Aws::Http::Standard::StandardHttpResponse>("DuckDBAwsHttp", request);

		try {
			// The AWS client factory is process-global, so this outlives the instance it was
			// registered for. Fail cleanly instead of using a destroyed DatabaseInstance.
			auto db_instance = db.lock();
			if (!db_instance) {
				throw InvalidConfigurationException(
				    "The DuckDB instance this AWS client was created for has been closed");
			}

			RequestType request_type;
			if (!TryGetRequestType(request->GetMethod(), request_type)) {
				throw NotImplementedException(
				    "HTTP method %s is not supported when AWS network calls are routed through DuckDB's HTTP layer",
				    Aws::Http::HttpMethodMapper::GetNameForHttpMethod(request->GetMethod()));
			}

			auto &http_util = GetTransport(*db_instance);
			string url = EnsureUrlHasPath(request->GetUri().GetURIString(true).c_str());

			auto params = http_util.InitializeParameters(*db_instance, url);
			// HTTPParams only picks up a logger from a ClientContext, and there is none here:
			// the SDK creates its HTTP client per AWS client, not per query. Attach the
			// database-wide logger so these requests still show up in duckdb_logs.
			if (!params->logger) {
				params->logger = db_instance->GetLogManager().GlobalLoggerReference();
			}
			ApplyClientConfig(*params);

			HTTPHeaders headers(*db_instance);
			for (const auto &header : request->GetHeaders()) {
				// Fetch forbids scripts from setting these and derives them itself (host from
				// the URL, content-length from the body). SigV4 signs 'host', but the browser
				// reproduces the same value, so the signature still validates.
				auto lower = StringUtil::Lower(header.first.c_str());
				if (lower == "host" || lower == "content-length") {
					continue;
				}
				// Assign rather than Insert(): HTTPHeaders pre-seeds DuckDB's User-Agent and
				// Insert() does not overwrite, which would drop the SDK's own user-agent.
				headers[header.first.c_str()] = header.second.c_str();
			}

			unique_ptr<HTTPClient> client;
			unique_ptr<HTTPResponse> response;
			string body_buffer;   // request body storage, kept alive across the call
			string response_body; // collected once, then written to the SDK response below

			// Going through HTTPUtil::Request (rather than calling client->Get/Post/... directly)
			// is what activates try_request, RunRequestWithRetry's backoff and LogRequest, and it
			// initializes the client for us, including the null-transport check.
			switch (request_type) {
			case RequestType::GET_REQUEST: {
				GetRequestInfo info(
				    url, headers, *params,
				    [&](const HTTPResponse &) {
					    // Reset per attempt: a retry replays the content handler from the start.
					    response_body.clear();
					    return true;
				    },
				    [&](const_data_ptr_t data, idx_t len) {
					    response_body.append(const_char_ptr_cast(data), len);
					    return true;
				    });
				info.try_request = true;
				response = http_util.Request(info, client);
				break;
			}
			case RequestType::POST_REQUEST: {
				body_buffer = ReadRequestBody(request);
				PostRequestInfo info(url, headers, *params, const_data_ptr_cast(body_buffer.c_str()),
				                     body_buffer.size());
				info.try_request = true;
				response = http_util.Request(info, client);
				// POST is the one method that buffers into buffer_out; the transports fill both
				// this and response->body, so take exactly one of them.
				response_body = std::move(info.buffer_out);
				break;
			}
			case RequestType::PUT_REQUEST: {
				body_buffer = ReadRequestBody(request);
				string content_type = request->GetContentType().c_str();
				PutRequestInfo info(url, headers, *params, const_data_ptr_cast(body_buffer.c_str()), body_buffer.size(),
				                    content_type);
				info.try_request = true;
				response = http_util.Request(info, client);
				break;
			}
			case RequestType::HEAD_REQUEST: {
				HeadRequestInfo info(url, headers, *params);
				info.try_request = true;
				response = http_util.Request(info, client);
				break;
			}
			case RequestType::DELETE_REQUEST: {
				DeleteRequestInfo info(url, headers, *params);
				info.try_request = true;
				response = http_util.Request(info, client);
				break;
			}
			default: {
				OptionsRequestInfo info(url, headers, *params);
				info.try_request = true;
				response = http_util.Request(info, client);
				break;
			}
			}

			// Hand the client back so httpfs can put the connection in its cache.
			http_util.CloseClient(std::move(client));

			if (!response) {
				aws_response->SetResponseCode(Aws::Http::HttpResponseCode::REQUEST_NOT_MADE);
				aws_response->SetClientErrorType(Aws::Client::CoreErrors::NETWORK_CONNECTION);
				aws_response->SetClientErrorMessage("No response received");
				return aws_response;
			}
			if (response->status == HTTPStatusCode::INVALID) {
				// No HTTP status came back at all: a connect/DNS/TLS failure, which try_request
				// returns as a response carrying request_error instead of throwing. Report it as
				// REQUEST_NOT_MADE with the message, so the SDK sees a retryable network error
				// rather than an unknown status 0 with no explanation.
				aws_response->SetResponseCode(Aws::Http::HttpResponseCode::REQUEST_NOT_MADE);
				aws_response->SetClientErrorType(Aws::Client::CoreErrors::NETWORK_CONNECTION);
				aws_response->SetClientErrorMessage(response->GetError().c_str());
				return aws_response;
			}

			aws_response->SetResponseCode(static_cast<Aws::Http::HttpResponseCode>(static_cast<int>(response->status)));
			for (const auto &header : response->headers) {
				aws_response->AddHeader(header.first.c_str(), header.second.c_str());
			}
			if (response_body.empty()) {
				response_body = std::move(response->body);
			}
			if (!response_body.empty()) {
				aws_response->GetResponseBody().write(response_body.data(),
				                                      NumericCast<int64_t>(response_body.size()));
			}
		} catch (std::exception &ex) {
			aws_response->SetResponseCode(Aws::Http::HttpResponseCode::REQUEST_NOT_MADE);
			aws_response->SetClientErrorType(Aws::Client::CoreErrors::NETWORK_CONNECTION);
			aws_response->SetClientErrorMessage(ex.what());
		}
		return aws_response;
	}

private:
	//! Carry over the parts of the SDK's ClientConfiguration that HTTPParams can express.
	//! connectTimeoutMs and caFile/caPath have no equivalent: the transport's own CA store
	//! and DuckDB's http settings govern those on this path.
	void ApplyClientConfig(HTTPParams &params) const {
		if (request_timeout_ms > 0) {
			auto timeout_ms = NumericCast<uint64_t>(request_timeout_ms);
			params.timeout = timeout_ms / 1000;
			params.timeout_usec = (timeout_ms % 1000) * 1000;
		}
		params.follow_location = follow_redirects;
		if (!verify_ssl) {
			params.override_verify_ssl = true;
			params.verify_ssl = false;
		}
		if (!proxy_host.empty()) {
			params.http_proxy = proxy_host;
			params.http_proxy_port = proxy_port;
			params.http_proxy_username = proxy_username;
			params.http_proxy_password = proxy_password;
		}
	}

private:
	weak_ptr<DatabaseInstance> db;
	long request_timeout_ms;
	bool verify_ssl;
	bool follow_redirects;
	string proxy_host;
	idx_t proxy_port;
	string proxy_username;
	string proxy_password;
};

class DuckDBAwsHttpClientFactory : public Aws::Http::HttpClientFactory {
public:
	explicit DuckDBAwsHttpClientFactory(weak_ptr<DatabaseInstance> db_p) : db(std::move(db_p)) {
	}

	void InitStaticState() override {
#if AWS_HTTP_SDK_FALLBACK_CURL
		EnsureCurlGlobalState();
#endif
	}

	void CleanupStaticState() override {
#if AWS_HTTP_SDK_FALLBACK_CURL
		if (curl_global_initialized.exchange(false)) {
			Aws::Http::CurlHttpClient::CleanupGlobalState();
		}
#endif
	}

	std::shared_ptr<Aws::Http::HttpClient>
	CreateHttpClient(const Aws::Client::ClientConfiguration &config) const override {
#if AWS_HTTP_SDK_FALLBACK
		auto db_instance = db.lock();
		if (db_instance && !NetworkCallsViaDuckDB(*db_instance)) {
			// Opt-out (native only): behave exactly as the SDK's default factory would.
#if AWS_HTTP_SDK_FALLBACK_CURL
			EnsureCurlGlobalState();
			return Aws::MakeShared<Aws::Http::CurlHttpClient>("DuckDBAwsHttp", config);
#else
			return Aws::MakeShared<Aws::Http::WinHttpSyncHttpClient>("DuckDBAwsHttp", config);
#endif
		}
#endif
		return Aws::MakeShared<DuckDBAwsHttpClient>("DuckDBAwsHttp", db, config);
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
	weak_ptr<DatabaseInstance> db;
};

} // namespace

void RegisterDuckDBAwsHttpClientFactory(DatabaseInstance &db) {
	// NOTE: Aws::Http::SetHttpClientFactory is process-global, so with several DatabaseInstances
	// in one process the last LOAD wins and all AWS traffic follows that instance's HTTP
	// settings. The weak_ptr keeps that from becoming a use-after-free when it is closed.
	weak_ptr<DatabaseInstance> weak_db = db.shared_from_this();
	Aws::Http::SetHttpClientFactory(Aws::MakeShared<DuckDBAwsHttpClientFactory>("DuckDBAwsHttp", weak_db));
}

} // namespace duckdb
