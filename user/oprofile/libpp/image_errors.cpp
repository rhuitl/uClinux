/**
 * @file image_errors.cpp
 * Report errors in images
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 */

#include "image_errors.h"

#include "arrange_profiles.h"
#include "string_manip.h"

#include <iostream>
#include <set>

using namespace std;

namespace {

set<string> reported_images_error;

}

void report_image_error(string const & image, image_error error, bool fatal)
{
	if (error == image_ok)
		return;

	if (reported_images_error.find(image) == reported_images_error.end()) {
		reported_images_error.insert(image);

		// FIXME: hacky
		if (error == image_not_found && is_prefix(image, "anon "))
			return;

		cerr << (fatal ? "error: " : "warning: ");
		cerr << image << ' ';

		switch (error) {
			case image_not_found:
				cerr << "could not be found.\n";
				break;

			case image_unreadable:
				cerr << "could not be read.\n";
				break;

			case image_multiple_match:
				cerr << "matches more than one file: "
				    "detailed profile will not be provided.\n";
				break;

			case image_format_failure:
				cerr << "is not in a usable binary format.\n";
				break;

			case image_ok:
				break;
		}
	}
}


void report_image_error(inverted_profile const & profile, bool fatal)
{
	report_image_error(profile.image, profile.error, fatal);
}


void report_image_errors(list<inverted_profile> const & plist)
{
	list<inverted_profile>::const_iterator it = plist.begin();
	list<inverted_profile>::const_iterator const end = plist.end();

	for (; it != end; ++it)
		report_image_error(*it, false);
}
