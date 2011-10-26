/**
 * @file opreport_options.cpp
 * Options for opreport tool
 *
 * @remark Copyright 2003 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
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
#include "opreport_options.h"
#include "popt_options.h"
#include "string_filter.h"
#include "file_manip.h"
#include "cverb.h"

using namespace std;

profile_classes classes;
profile_classes classes2;

namespace options {
	string archive_path;
	string archive_path2;
	demangle_type demangle = dmt_normal;
	bool symbols;
	bool callgraph;
	bool debug_info;
	bool details;
	bool exclude_dependent;
	string_filter symbol_filter;
	sort_options sort_by;
	merge_option merge_by;
	bool show_header = true;
	bool long_filenames;
	bool show_address;
	bool accumulated;
	bool reverse_sort;
	bool global_percent;
}


namespace {

string outfile;
vector<string> mergespec;
vector<string> sort;
vector<string> exclude_symbols;
vector<string> include_symbols;
string demangle_option = "normal";

popt::option options_array[] = {
	popt::option(options::callgraph, "callgraph", 'c',
	             "show call graph"),
	popt::option(options::details, "details", 'd',
		     "output detailed samples for each symbol"),
	popt::option(options::symbols, "symbols", 'l',
		     "list all symbols"),

	popt::option(outfile, "output-file", 'o',
	             "output to the given filename", "file"),

	popt::option(sort, "sort", 's',
		     "sort by", "sample,image,app-name,symbol,debug,vma"),
	popt::option(options::reverse_sort, "reverse-sort", 'r',
		     "use reverse sort"),
	popt::option(mergespec, "merge", 'm',
		     "comma separated list", "cpu,lib,tid,tgid,unitmask,all"),
	popt::option(options::exclude_dependent, "exclude-dependent", 'x',
		     "exclude libs, kernel, and module samples for applications"),
	popt::option(exclude_symbols, "exclude-symbols", 'e',
		     "exclude these comma separated symbols", "symbols"),
	popt::option(include_symbols, "include-symbols", 'i',
		     "include these comma separated symbols", "symbols"),
	popt::option(options::threshold_opt, "threshold", 't',
		     "minimum percentage needed to produce output",
		     "percent"),

	popt::option(demangle_option, "demangle", 'D',
		     "demangle GNU C++ symbol names (default normal)",
	             "none|normal|smart"),
	// PP:5
	popt::option(options::debug_info, "debug-info", 'g',
		     "add source file and line number to output"),
	popt::option(options::show_header, "no-header", 'n',
		     "remove all headers from output"),
	popt::option(options::show_address, "show-address", 'w',
	             "show VMA address of each symbol"),
	popt::option(options::long_filenames, "long-filenames", 'f',
		     "show the full path of filenames"),
	popt::option(options::accumulated, "accumulated", 'a',
		     "percentage field show accumulated count"),
	popt::option(options::global_percent, "global-percent", '%',
		     "percentage are not relative to symbol count or image "
		     "count but total sample count"),
};


void handle_sort_option()
{
	if (sort.empty()) {
		// PP:5.14 sort default to sample
		sort.push_back("sample");
	}

	vector<string>::const_iterator cit = sort.begin();
	vector<string>::const_iterator end = sort.end();

	for (; cit != end; ++cit)
		options::sort_by.add_sort_option(*cit);
}


void handle_output_file()
{
	if (outfile.empty())
		return;

	static ofstream os(outfile.c_str());
	if (!os) {
		cerr << "Couldn't open \"" << outfile
		     << "\" for writing." << endl;
		exit(EXIT_FAILURE);
	}

	cout.rdbuf(os.rdbuf());
}


///  Check incompatible or meaningless options.
void check_options(bool diff)
{
	using namespace options;

	bool do_exit = false;

	if (callgraph) {
		symbols = true;
		if (details) {
			cerr << "--callgraph is incompatible with --details" << endl;
			do_exit = true;
		}

		if (diff) {
			cerr << "differential profiles are incompatible with --callgraph" << endl;
			do_exit = true;
		}
	}

	if (details && diff) {
		cerr << "differential profiles are incompatible with --details" << endl;
		do_exit = true;
	}

	if (!symbols) {
		if (diff) {
			cerr << "different profiles are meaningless "
				"without --symbols" << endl;
			do_exit = true;
		}

		if (show_address) {
			cerr << "--show-address is meaningless "
				"without --symbols" << endl;
			do_exit = true;
		}

		if (debug_info || accumulated) {
			cerr << "--debug-info and --accumulated are "
			     << "meaningless without --symbols" << endl;
			do_exit = true;
		}

		if (!exclude_symbols.empty() || !include_symbols.empty()) {
			cerr << "--exclude-symbols and --include-symbols are "
			     << "meaningless without --symbols" << endl;
			do_exit = true;
		}

		if (find(sort_by.options.begin(), sort_by.options.end(), 
			 sort_options::vma) != sort_by.options.end()) {
			cerr << "--sort=vma is "
			     << "meaningless without --symbols" << endl;
			do_exit = true;
		}
	}

	if (global_percent && symbols && !(details || callgraph)) {
		cerr << "--global-percent is meaningless with --symbols "
		        "and without --details or --callgraph" << endl;
		do_exit = true;
	}

	if (do_exit)
		exit(EXIT_FAILURE);
}


/// process a spec into classes
string process_spec(profile_classes & classes, list<string> const & spec)
{
	using namespace options;

	copy(spec.begin(), spec.end(),
	     ostream_iterator<string>(cverb << vsfile, " "));
	cverb << vsfile << "\n\n";

	profile_spec const pspec =
		profile_spec::create(spec, extra_found_images);

	list<string> sample_files = pspec.generate_file_list(exclude_dependent,
	                                                     !options::callgraph);

	cverb << vsfile << "Archive: " << pspec.get_archive_path() << endl;

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

	return pspec.get_archive_path();
}


} // namespace anon


void handle_options(options::spec const & spec)
{
	using namespace options;

	if (details) {
		symbols = true;
		show_address = true;
	}

	handle_sort_option();
	merge_by = handle_merge_option(mergespec, true, exclude_dependent);
	handle_output_file();
	demangle = handle_demangle_option(demangle_option);
	check_options(spec.first.size());

	symbol_filter = string_filter(include_symbols, exclude_symbols);

	if (!spec.first.size()) {
		archive_path = process_spec(classes, spec.common);
	} else {
		cverb << vsfile << "profile spec 1:" << endl;
		archive_path = process_spec(classes, spec.first);
		cverb << vsfile << "profile spec 2:" << endl;
		archive_path2 = process_spec(classes2, spec.second);

		if (!classes.matches(classes2)) {
			cerr << "profile classes are incompatible" << endl;
			exit(EXIT_FAILURE);
		}
	}
}
