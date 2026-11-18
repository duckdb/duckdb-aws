#pragma once

#include "duckdb/common/common.hpp"

namespace duckdb {

class ClientContext;
class DatabaseInstance;

//! An extension published by a host through its extension repository (`CREATE EXTENSION REPOSITORY <host>`), such as
//! the redshift extension at aws.amazon.com. Loading it is a `LOAD <extension> FROM <host>`, with two checks in front:
//! the repository named after the host must be the host's own (resolved from the host, not added with a prefix and
//! keys of the caller's choosing), and the extension must have been installed from it. Nothing here creates a
//! repository or installs anything; the errors say what to run.
struct HostExtension {
	HostExtension(string extension_name_p, string host_p)
	    : extension_name(std::move(extension_name_p)), host(std::move(host_p)) {
	}

	string extension_name;
	string host;

	//! Refuse a repository that only carries the host's name: one added with a prefix, whose keys are not the host's.
	//! `purpose` opens the message, e.g. "Attaching 'arn:aws:...'"
	void RequireRepositoryIsTheHost(DatabaseInstance &db, const string &purpose) const;
	//! Whether `INSTALL <extension> FROM <host>` has been run: the installed file sits in the repository's own folder
	bool IsInstalled(DatabaseInstance &db) const;
	//! Load the extension from the host's repository, after both checks; a Missing Extension error names the
	//! statements to run when it is not installed. `alternative`, if given, is appended as the other way to proceed
	void Load(ClientContext &context, const string &purpose, const string &alternative = string()) const;
};

} // namespace duckdb
