/**
 * @file image_errors.h
 * Report errors in images
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 */

#ifndef IMAGE_ERRORS_H
#define IMAGE_ERRORS_H

#include <list>
#include <string>

class inverted_profile;

/// possible reasons why we can't read a binary image
enum image_error {
	image_ok = 0,
	image_not_found,
	image_unreadable,
	image_format_failure,
	image_multiple_match
};

/// output why the image passed can't be read to stderr, we warranty only one
/// error report by image name.
void
report_image_error(std::string const & image, image_error error, bool fatal);

/// output why the image passed can't be read to stderr
void report_image_error(inverted_profile const & profile, bool fatal);

/// output why any bad images can't be read to stderr
void report_image_errors(std::list<inverted_profile> const & plist);

#endif /* IMAGE_ERRORS_H */
