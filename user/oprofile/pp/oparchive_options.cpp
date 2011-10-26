/**
 * @file oparchive_options.cpp
 * Options for oparchive tool
 *
 * @remark Copyright 2002, 2003, 2004 OProfile authors
 * @remark Read the file COPYING
 *
 * @author William Cohen
 * @author Philippe Elie
 */

#include <vector>
#include <list>
#include <iostream>
#include <algorithm>
#include <iterator>
#include <fstream>

#include "profile_spec.h"
#include "arrange_profiles.h"
#include "oparchive_options.h"
#include "popt_options.h"
#include "string_filter.h"
#include "file_manip.h"
#include "cverb.h"


using namespace std;

profile_classes classes;
list<string> sample_files;

namespace options {
	string archive_path;
	bool exclude_dependent;
	merge_option merge_by;
	string outdirectory;
}


namespace {

vector<string> mergespec;

popt::option options_array[] = {
	popt::option(options::outdirectory, "output-directory", 'o',
	             "output to the given directory", "directory"),
	popt::option(options::exclude_dependent, "exclude-dependent", 'x',
		     "exclude libs, kernel, and module samples for applications")
};


/**
 * check incompatible or meaningless options
 *
 */
void check_options()
{
	using namespace options;

	/* output directory is required */
	if (outdirectory.size() == 0) {
		cerr << "Requires --output-directory option." << endl;
		exit(EXIT_FAILURE);
	}
}

}  // anonymous namespace


void handle_options(options::spec const & spec)
{
	using namespace options;

	if (spec.first.size()) {
		cerr << "differential profiles not allowed" << endl;
		exit(EXIT_FAILURE);
	}

	// merging doesn't occur in oparchive but we must allow it to avoid
	// triggering sanity checking in arrange_profiles()
	merge_by.cpu = true;
	merge_by.lib = true;
	merge_by.tid = true;
	merge_by.tgid = true;
	merge_by.unitmask = true;
	check_options();

	profile_spec const pspec =
		profile_spec::create(spec.common, extra_found_images);

	sample_files = pspec.generate_file_list(exclude_dependent, false);

	archive_path = pspec.get_archive_path();
	cverb << vsfile << "Archive: " << archive_path << endl;

	cverb << vsfile << "Matched sample files: " << sample_files.size()
	      << endl;
	copy(sample_files.begin(), sample_files.end(),
	     ostream_iterator<string>(cverb << vsfile, "\n"));

	classes = arrange_profiles(sample_files, merge_by);

	cverb << vsfile << "profile_classes:\n" << classes << endl;

	if (classes.v.empty()) {
		cerr << "error: no sample files found: profile specification "
		     "too strict ?" << endl;
		exit(EXIT_FAILURE);
	}
}
