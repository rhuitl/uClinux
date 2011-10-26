/**
 * @file oparchive.cpp
 * Implement oparchive utility
 *
 * @remark Copyright 2003, 2004 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Will Cohen
 * @author John Levon
 * @author Philippe Elie
 */

#include <iostream>
#include <fstream>

#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "op_file.h"
#include "op_bfd.h"
#include "op_config.h"
#include "oparchive_options.h"
#include "file_manip.h"
#include "cverb.h"
#include "image_errors.h"
#include "string_manip.h"

using namespace std;

namespace {


void copy_one_file(image_error err, string const & source, string const & dest)
{
	if (!copy_file(source, dest) && err == image_ok) {
		cerr << "can't copy from " << source << " to " << dest
		     << " cause: " << strerror(errno) << endl;
	}
}

int oparchive(options::spec const & spec)
{
	handle_options(spec);

	/* Check to see if directory can be created */
	if (create_path(options::outdirectory.c_str())) {
		cerr << "Unable to create directory for " 
		     <<	options::outdirectory << "." << endl;
		exit (EXIT_FAILURE);
	}

	/* copy over each of the executables and the debuginfo files */
	list<inverted_profile> iprofiles
		= invert_profiles(options::archive_path, classes,
				  options::extra_found_images);

	report_image_errors(iprofiles);

	list<inverted_profile>::iterator it = iprofiles.begin();
	list<inverted_profile>::iterator const end = iprofiles.end();

	cverb << vdebug << "(exe_names)" << endl << endl;
	for (; it != end; ++it) {
		string exe_name = it->image;
		string exe_archive_file = options::outdirectory + exe_name;

		// FIXME: hacky
		if (it->error == image_not_found && is_prefix(exe_name, "anon "))
			continue;

		cverb << vdebug << exe_name << endl;
		/* Create directory for executable file. */
		if (create_path(exe_archive_file.c_str())) {
			cerr << "Unable to create directory for "
			     << exe_archive_file << "." << endl;
			exit (EXIT_FAILURE);
		}

		/* Copy actual executable files */
		copy_one_file(it->error, options::archive_path + exe_name,
		              exe_archive_file);

		/* If there are any debuginfo files, copy them over.
		 * Need to copy the debug info file in the same
		 * directory as the executable. The /usr/lib/debug
		 *  search path is not going to work.
		 */
		bfd * ibfd = open_bfd(exe_name);
		if (ibfd) {
			string global(options::archive_path + DEBUGDIR);
			string dirname = op_dirname(options::archive_path + 
						    exe_name);
			string debug_filename;
			if (find_separate_debug_file(ibfd, dirname, global,
				debug_filename)) {
				/* found something copy it over */
				string dest_debug = options::outdirectory +
					dirname + "/" +
					op_basename(debug_filename);
				copy_one_file(image_ok, debug_filename, dest_debug);
			}
			bfd_close(ibfd);
		}
	}

	/* copy over each of the sample files */
	list<string>::iterator sit = sample_files.begin();
	list<string>::iterator const send = sample_files.end();

	cverb << vdebug << "(sample_names)" << endl << endl;

	for (; sit != send; ++sit) {
		string sample_name = *sit;
		string sample_base = sample_name;
		/* Get rid of the the archive_path from the name */
		sample_base.replace(sample_base.find(options::archive_path),
				    options::archive_path.size(), "");
		string sample_archive_file = options::outdirectory + sample_base;
		
		cverb << vdebug << (sample_name) << endl;
		cverb << vdebug << " destp " << sample_archive_file << endl;
		if (create_path(sample_archive_file.c_str())) {
			cerr << "Unable to create directory for "
			     <<	sample_archive_file << "." << endl;
			exit (EXIT_FAILURE);
		}

		/* Copy over actual sample file. */
		copy_one_file(image_ok, sample_name, sample_archive_file);
	}

	/* copy over the /var/lib/oprofile/abi file if it exists */
	string abi_name = "/var/lib/oprofile/abi";
	copy_one_file(image_ok, options::archive_path + abi_name,
	              options::outdirectory + abi_name);

	/* copy over the /var/lib/oprofile/oprofiled.log file */
	string log_name = "/var/lib/oprofile/oprofiled.log";
	copy_one_file(image_ok, options::archive_path + log_name,
	              options::outdirectory + log_name);

	return 0;
}

}  // anonymous namespace


int main(int argc, char const * argv[])
{
	run_pp_tool(argc, argv, oparchive);
}
