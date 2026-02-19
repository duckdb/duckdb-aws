#pragma once

#include "duckdb.hpp"

namespace duckdb {

struct AwsSetCredentialsResult {
	string set_access_key_id;
	string set_secret_access_key;
	string set_session_token;
	string set_region;
};

class AwsExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
};

} // namespace duckdb
