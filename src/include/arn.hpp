#pragma once

#include "duckdb/common/common.hpp"

namespace duckdb {

//! arn:<partition>:<service>:<region>:<account>:<resource>
struct ParsedArn {
	string raw;
	string partition;
	string service;
	string region;
	string account_id;
	//! Everything after the 5th ':', may itself contain ':' or '/'
	string resource;

	//! Whether a path is spelled as an ARN (so that a backend reads region, account and resource from it)
	static bool IsArn(const string &path);
	//! Parse an ARN, lowercasing the service; throws when the shape is not an ARN
	static ParsedArn Parse(const string &arn);
};

} // namespace duckdb
