#pragma once

#include "duckdb.hpp"

namespace duckdb {

class AwsExtension : public Extension {
public:
	void Load(ExtensionLoader &db) override;
	std::string Name() override;
};

} // namespace duckdb
