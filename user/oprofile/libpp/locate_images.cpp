/**
 * @file locate_images.cpp
 * Command-line helper
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 * @author John Levon
 */

#include "file_manip.h"
#include "locate_images.h"

#include <cerrno>
#include <iostream>
#include <sstream>
#include <cstdlib>

using namespace std;


void extra_images::populate(vector<string> const & paths)
{
	vector<string>::const_iterator cit = paths.begin();
	vector<string>::const_iterator end = paths.end();
	for (; cit != end; ++cit) {
		string const path = op_realpath(*cit);
		list<string> file_list;
		create_file_list(file_list, path, "*", true);
		list<string>::const_iterator lit = file_list.begin();
		list<string>::const_iterator lend = file_list.end();
		for (; lit != lend; ++lit) {
			value_type v(op_basename(*lit), op_dirname(*lit));
			images.insert(v);
		}
	}
}


vector<string> const extra_images::find(string const & name) const
{
	extra_images::matcher match(name);
	return find(match);
}


vector<string> const
extra_images::find(extra_images::matcher const & match) const
{
	vector<string> matches;

	const_iterator cit = images.begin();
	const_iterator end = images.end();

	for (; cit != end; ++cit) {
		if (match(cit->first))
			matches.push_back(cit->second + '/' + cit->first);
	}

	return matches;
}


namespace {

/**
 * Function object for matching a module filename, which
 * has its own special mangling rules in 2.6 kernels.
 */
struct module_matcher : public extra_images::matcher {
public:
	explicit module_matcher(string const & s)
		: extra_images::matcher(s) {}

	virtual bool operator()(string const & candidate) const {
		if (candidate.length() != value.length())
			return false;

		for (string::size_type i = 0 ; i < value.length() ; ++i) {
			if (value[i] == candidate[i])
				continue;
			if (value[i] == '_' &&
				(candidate[i] == ',' || candidate[i] == '-'))
				continue;
			return false;
		}

		return true;
	}
};

} // anon namespace


string const find_image_path(string const & archive_path,
			     string const & image_name,
                             extra_images const & extra_images,
                             image_error & error)
{
	error = image_ok;

	string const image = op_realpath(archive_path + image_name);

	// simplest case
	if (op_file_readable(image)) {
		error = image_ok;
		return image_name;
	}

	if (errno == EACCES) {
		error = image_unreadable;
		return image_name;
	}

	string const base = op_basename(image);

	vector<string> result = extra_images.find(base);

	// not found, try a module search
	if (result.empty())
		result = extra_images.find(module_matcher(base + ".ko"));

	if (result.empty()) {
		error = image_not_found;
		return image_name;
	}

	if (result.size() > 1) {
		error = image_multiple_match;
		return image_name;
	}

	return result[0];
}
