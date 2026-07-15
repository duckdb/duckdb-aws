#include "utils/utils.hpp"

#include "aws_client.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/extension_helper.hpp"

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

const vector<string> &GetDefaultAwsRegions() {
	// FIXME: hardcoded, default-enabled commercial regions only. Replace with live enumeration
	// (ec2:DescribeRegions or account:ListRegions) so newly-enabled opt-in regions are picked up automatically
	// and aws-cn / aws-us-gov callers get their own partition's regions (a client's credentials are partition-
	// scoped, so DescribeRegions run from the caller's region is inherently partition-correct). Blocked on
	// linking the ec2 (or account) SDK component, which is not currently built. Until then, a caller using
	// non-commercial credentials sees every region below fail as an `error` sentinel row.
	static const vector<string> regions = {
	    "us-east-1",      "us-east-2",      "us-west-1",      "us-west-2",      "ca-central-1", "sa-east-1",
	    "eu-west-1",      "eu-west-2",      "eu-west-3",      "eu-central-1",   "eu-north-1",   "ap-south-1",
	    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-southeast-1", "ap-southeast-2"};
	return regions;
}

const vector<string> &AwsSecretTypes() {
	static const vector<string> aws_secret_types = {"aws", "s3"};
	return aws_secret_types;
}

bool IsAwsSecretType(const string &type) {
	for (const auto &candidate : AwsSecretTypes()) {
		if (type == candidate) {
			return true;
		}
	}
	return false;
}

unique_ptr<SecretEntry> FindAwsSecret(ClientContext &context, const string &secret_name) {
	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);

	if (!secret_name.empty()) {
		auto secret_entry = secret_manager.GetSecretByName(transaction, secret_name);
		if (!secret_entry) {
			throw BinderException("Secret with name \"%s\" not found", secret_name);
		}
		const auto &type = secret_entry->secret->GetType().GetIdentifierName();
		if (!IsAwsSecretType(type)) {
			throw BinderException("Secret \"%s\" is of type \"%s\", but an AWS identity is required; pass a secret of "
			                      "type \"aws\" or \"s3\"",
			                      secret_name, type);
		}
		return secret_entry;
	}

	auto all_secrets = secret_manager.AllSecrets(transaction);
	for (const auto &wanted_type : AwsSecretTypes()) {
		vector<const SecretEntry *> matches;
		for (const auto &entry : all_secrets) {
			if (entry.secret->GetType().GetIdentifierName() == wanted_type) {
				matches.push_back(&entry);
			}
		}
		if (matches.size() > 1) {
			throw BinderException("Found %d secrets of type \"%s\"; name the one to use with a SECRET option",
			                      matches.size(), wanted_type);
		}
		if (matches.size() == 1) {
			return make_uniq<SecretEntry>(*matches[0]);
		}
	}
	throw BinderException("No AWS credentials found. Create a secret holding them, e.g. "
	                      "CREATE SECRET (TYPE aws, PROVIDER credential_chain, REGION '<region>')");
}

const char *const POSTGRES_EXTENSION_NAME = "postgres";

optional_ptr<StorageExtension> FindPostgresStorageExtension(const DBConfig &config) {
	// Registered as "postgres_scanner", which is what "postgres" aliases to.
	return StorageExtension::Find(config, ExtensionHelper::ApplyExtensionAlias(POSTGRES_EXTENSION_NAME));
}

} // namespace duckdb
