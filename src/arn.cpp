#include "arn.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {

bool ParsedArn::IsArn(const string &path) {
	return StringUtil::CIStartsWith(path, "arn:");
}

ParsedArn ParsedArn::Parse(const string &arn) {
	string fields[5];
	idx_t field = 0;
	idx_t start = 0;
	//! NOTE: we can't use StringUtil::Split because it doesn't keep empty items
	for (idx_t i = 0; i < arn.size() && field < 5; i++) {
		if (arn[i] == ':') {
			fields[field++] = arn.substr(start, i - start);
			start = i + 1;
		}
	}
	if (field < 5 || fields[0] != "arn") {
		throw InvalidInputException(
		    "Expected an AWS ARN of the form 'arn:<partition>:<service>:<region>:<account>:<resource>', got '%s'", arn);
	}

	ParsedArn result;
	result.raw = arn;
	result.partition = fields[1];
	if (result.partition.empty()) {
		throw InvalidInputException("Invalid PARTITION Section of ARN: '%s'", result.partition);
	}
	// All valid service identifiers are lowercase,
	// let's be helpful and lowercase instead of throwing an error for non-lowercase service components.
	result.service = StringUtil::Lower(fields[2]);
	result.region = fields[3];
	result.account_id = fields[4];
	result.resource = arn.substr(start);
	return result;
}

} // namespace duckdb
