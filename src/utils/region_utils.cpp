#include "utils/region_utils.hpp"

#include "aws_client.hpp"

#include "duckdb/main/client_context.hpp"

#include <cstdlib>

namespace duckdb {

namespace {

string RegionFromSetting(ClientContext &context) {
	Value s3_region_setting;
	if (context.TryGetCurrentSetting("s3_region", s3_region_setting)) {
		return s3_region_setting.ToString();
	}
	return "";
}

string RegionFromEnvironment() {
	if (const char *env = getenv("AWS_REGION")) {
		return env;
	}
	if (const char *env = getenv("AWS_DEFAULT_REGION")) {
		return env;
	}
	return "";
}

string RegionFromProfile(const string &profile_name) {
	auto profile = GetAwsProfile(profile_name.empty() ? "default" : profile_name, false);
	return profile.GetRegion().c_str();
}

} // namespace

string ResolveAwsRegion(ClientContext &context, const string &explicit_region, const string &profile_name) {
	if (!explicit_region.empty()) {
		return explicit_region;
	}
	auto region = RegionFromSetting(context);
	if (!region.empty()) {
		return region;
	}
	region = RegionFromEnvironment();
	if (!region.empty()) {
		return region;
	}
	return RegionFromProfile(profile_name);
}

} // namespace duckdb
