/**
 * @file format_output.cpp
 * outputting format for symbol lists
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 * @author John Levon
 */

/* older glibc has C99 INFINITY in _GNU_SOURCE */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sstream>
#include <iomanip>
#include <iostream>
#include <cmath>

#include "string_manip.h"

#include "format_output.h"
#include "profile_container.h"
#include "callgraph_container.h"
#include "diff_container.h"

using namespace std;


namespace {

string const & get_image_name(image_name_id id, bool lf)
{
	return lf ? image_names.name(id) : image_names.basename(id);
}

string const get_linenr_info(file_location const floc, bool lf)
{
	ostringstream out;

	string const & filename = lf
		? debug_names.name(floc.filename)
		: debug_names.basename(floc.filename);

	if (!filename.empty()) {
		out << filename << ":" << floc.linenr;
	} else {
		out << "(no location information)";
	}

	return out.str();
}

string get_vma(bfd_vma vma, bool vma_64)
{
	ostringstream out;
	int width = vma_64 ? 16 : 8;

	out << hex << setw(width) << setfill('0') << vma;

	return out.str();
}

string get_percent(count_type dividend, count_type divisor)
{
	double ratio = op_ratio(dividend, divisor);

	return ::format_percent(ratio * 100, percent_int_width,
	                     percent_fract_width);
}

} // anonymous namespace


namespace format_output {


formatter::formatter()
	:
	nr_classes(1),
	flags(ff_none),
	vma_64(false),
	long_filenames(false),
	need_header(true)
{
	format_map[ff_vma] = field_description(9, "vma", &formatter::format_vma);
	format_map[ff_nr_samples] = field_description(9, "samples", &formatter::format_nr_samples);
	format_map[ff_nr_samples_cumulated] = field_description(14, "cum. samples", &formatter::format_nr_cumulated_samples);
	format_map[ff_percent] = field_description(9, "%", &formatter::format_percent);
	format_map[ff_percent_cumulated] = field_description(11, "cum. %", &formatter::format_cumulated_percent);
	format_map[ff_linenr_info] = field_description(28, "linenr info", &formatter::format_linenr_info);
	format_map[ff_image_name] = field_description(25, "image name", &formatter::format_image_name);
	format_map[ff_app_name] = field_description(25, "app name", &formatter::format_app_name);
	format_map[ff_symb_name] = field_description(30, "symbol name", &formatter::format_symb_name);
	format_map[ff_percent_details] = field_description(9, "%", &formatter::format_percent_details);
	format_map[ff_percent_cumulated_details] = field_description(10, "cum. %", &formatter::format_cumulated_percent_details);
	format_map[ff_diff] = field_description(10, "diff %", &formatter::format_diff);
}


formatter::~formatter()
{
}


void formatter::set_nr_classes(size_t nr)
{
	nr_classes = nr;
}


void formatter::add_format(format_flags flag)
{
	flags = static_cast<format_flags>(flags | flag);
}


void formatter::show_header(bool on_off)
{
	need_header = on_off;
}
 

void formatter::vma_format_64bit(bool on_off)
{
	vma_64 = on_off;
}


void formatter::show_long_filenames(bool on_off)
{
	long_filenames = on_off;
}


void formatter::show_global_percent(bool on_off)
{
	global_percent = on_off;
}


void formatter::output_header(ostream & out)
{
	if (!need_header)
		return;

	size_t padding = 0;

	// first output the vma field
	if (flags & ff_vma)
		padding = output_header_field(out, ff_vma, padding);

	// the field repeated for each profile class
	for (size_t pclass = 0 ; pclass < nr_classes; ++pclass) {
		if (flags & ff_nr_samples)
			padding = output_header_field(out,
			      ff_nr_samples, padding);

		if (flags & ff_nr_samples_cumulated)
			padding = output_header_field(out, 
			       ff_nr_samples_cumulated, padding);

		if (flags & ff_percent)
			padding = output_header_field(out,
			       ff_percent, padding);

		if (flags & ff_percent_cumulated)
			padding = output_header_field(out,
			       ff_percent_cumulated, padding);

		if (flags & ff_diff)
			padding = output_header_field(out,
				ff_diff, padding);

		if (flags & ff_percent_details)
			padding = output_header_field(out,
			       ff_percent_details, padding);

		if (flags & ff_percent_cumulated_details)
			padding = output_header_field(out,
			       ff_percent_cumulated_details, padding);
	}

	// now the remaining field
	if (flags & ff_linenr_info)
		padding = output_header_field(out, ff_linenr_info, padding);

	if (flags & ff_image_name)
		padding = output_header_field(out, ff_image_name, padding);

	if (flags & ff_app_name)
		padding = output_header_field(out, ff_app_name, padding);

	if (flags & ff_symb_name)
		padding = output_header_field(out, ff_symb_name, padding);

	out << "\n";
}


/// describe each possible field of colummned output.
// FIXME: use % of the screen width here. sum of % equal to 100, then calculate
// ratio between 100 and the selected % to grow non fixed field use also
// lib[n?]curses to get the console width (look info source) (so on add a fixed
// field flags)
size_t formatter::
output_field(ostream & out, field_datum const & datum,
             format_flags fl, size_t padding, bool hide_immutable)
{
	if (!hide_immutable) {
		out << string(padding, ' ');

		field_description const & field(format_map[fl]);
		string str = (this->*field.formatter)(datum);
		out << str;

		// at least one separator char
		padding = 1;
		if (str.length() < field.width)
			padding = field.width - str.length();
	} else {
		field_description const & field(format_map[fl]);
		padding += field.width;
	}

	return padding;
}

 
size_t formatter::
output_header_field(ostream & out, format_flags fl, size_t padding)
{
	out << string(padding, ' ');

	field_description const & field(format_map[fl]);
	out << field.header_name;

	// at least one separator char
	padding = 1;
	if (field.header_name.length() < field.width)
		padding = field.width - field.header_name.length();

	return padding;
}
 

string formatter::format_vma(field_datum const & f)
{
	return get_vma(f.sample.vma, vma_64);
}

 
string formatter::format_symb_name(field_datum const & f)
{
	return symbol_names.demangle(f.symbol.name);
}


string formatter::format_image_name(field_datum const & f)
{
	return get_image_name(f.symbol.image_name, long_filenames);
}

 
string formatter::format_app_name(field_datum const & f)
{
	return get_image_name(f.symbol.app_name, long_filenames);
}

 
string formatter::format_linenr_info(field_datum const & f)
{
	return get_linenr_info(f.sample.file_loc, long_filenames);
}

 
string formatter::format_nr_samples(field_datum const & f)
{
	ostringstream out;
	out << f.sample.counts[f.pclass];
	return out.str();
}

 
string formatter::format_nr_cumulated_samples(field_datum const & f)
{
	if (f.diff == -INFINITY)
		return "---";
	ostringstream out;
	f.counts.cumulated_samples[f.pclass] += f.sample.counts[f.pclass];
	out << f.counts.cumulated_samples[f.pclass];
	return out.str();
}

 
string formatter::format_percent(field_datum const & f)
{
	if (f.diff == -INFINITY)
		return "---";
	return get_percent(f.sample.counts[f.pclass], f.counts.total[f.pclass]);
}

 
string formatter::format_cumulated_percent(field_datum const & f)
{
	if (f.diff == -INFINITY)
		return "---";
	f.counts.cumulated_percent[f.pclass] += f.sample.counts[f.pclass];

	return get_percent(f.counts.cumulated_percent[f.pclass],
	                   f.counts.total[f.pclass]);
}

 
string formatter::format_percent_details(field_datum const & f)
{
	return get_percent(f.sample.counts[f.pclass],
		f.counts.total[f.pclass]);
}

 
string formatter::format_cumulated_percent_details(field_datum const & f)
{
	f.counts.cumulated_percent_details[f.pclass] += f.sample.counts[f.pclass];

	return get_percent(f.counts.cumulated_percent_details[f.pclass],
	                   f.counts.total[f.pclass]);
}


string formatter::format_diff(field_datum const & f)
{
	if (f.diff == INFINITY) {
		ostringstream out;
		out << "+++";
		return out.str();
	} else if (f.diff == -INFINITY) {
		ostringstream out;
		out << "---";
		return out.str();
	}

	return ::format_percent(f.diff, percent_int_width,
                                percent_fract_width, true);
}


void formatter::
do_output(ostream & out, symbol_entry const & symb, sample_entry const & sample,
          counts_t & c, diff_array_t const & diffs, bool hide_immutable)
{
	size_t padding = 0;

	// first output the vma field
	field_datum datum(symb, sample, 0, c);
	if (flags & ff_vma)
		padding = output_field(out, datum, ff_vma, padding, false);

	// repeated fields for each profile class
	for (size_t pclass = 0 ; pclass < nr_classes; ++pclass) {
		field_datum datum(symb, sample, pclass, c, diffs[pclass]);

		if (flags & ff_nr_samples)
			padding = output_field(out, datum,
			       ff_nr_samples, padding, false);

		if (flags & ff_nr_samples_cumulated)
			padding = output_field(out, datum, 
			       ff_nr_samples_cumulated, padding, false);

		if (flags & ff_percent)
			padding = output_field(out, datum,
			       ff_percent, padding, false);

		if (flags & ff_percent_cumulated)
			padding = output_field(out, datum,
			       ff_percent_cumulated, padding, false);

		if (flags & ff_diff)
			padding = output_field(out, datum,
				ff_diff, padding, false);

		if (flags & ff_percent_details)
			padding = output_field(out, datum,
			       ff_percent_details, padding, false);

		if (flags & ff_percent_cumulated_details)
			padding = output_field(out, datum,
			       ff_percent_cumulated_details, padding, false);
	}

	// now the remaining field
	if (flags & ff_linenr_info)
		padding = output_field(out, datum, ff_linenr_info,
		       padding, false);

	if (flags & ff_image_name)
		padding = output_field(out, datum, ff_image_name,
		       padding, hide_immutable);

	if (flags & ff_app_name)
		padding = output_field(out, datum, ff_app_name,
		       padding, hide_immutable);

	if (flags & ff_symb_name)
		padding = output_field(out, datum, ff_symb_name,
		       padding, hide_immutable);

	out << "\n";
}
 

opreport_formatter::opreport_formatter(profile_container const & p)
	:
	profile(p),
	need_details(false)
{
	counts.total = profile.samples_count();
}

 
void opreport_formatter::show_details(bool on_off)
{
	need_details = on_off;
}


void opreport_formatter::output(ostream & out, symbol_entry const * symb)
{
	do_output(out, *symb, symb->sample, counts);

	if (need_details)
		output_details(out, symb);
}


void opreport_formatter::
output(ostream & out, symbol_collection const & syms)
{
	output_header(out);

	symbol_collection::const_iterator it = syms.begin();
	symbol_collection::const_iterator end = syms.end();
	for (; it != end; ++it)
		output(out, *it);
}


void opreport_formatter::
output_details(ostream & out, symbol_entry const * symb)
{
	counts_t c = counts;

	if (!global_percent)
		c.total = symb->sample.counts;

	// cumulated percent are relative to current symbol.
	c.cumulated_samples = count_array_t();
	c.cumulated_percent = count_array_t();

	sample_container::samples_iterator it = profile.begin(symb);
	sample_container::samples_iterator end = profile.end(symb);
	for (; it != end; ++it) {
		out << "  ";
		do_output(out, *symb, it->second, c, diff_array_t(), true);
	}
}

 
cg_formatter::cg_formatter(callgraph_container const & profile)
{
	counts.total = profile.samples_count();
}


void cg_formatter::output(ostream & out, cg_collection const & syms)
{
	// amount of spacing prefixing child and parent lines
	string const child_parent_prefix("  ");

	output_header(out);

	out << string(79, '-') << endl;

	cg_collection::const_iterator it;
	cg_collection::const_iterator end = syms.end();

	for (it = syms.begin(); it < end; ++it) {
		cg_symbol const & sym = *it;

		cg_symbol::children::const_iterator cit;
		cg_symbol::children::const_iterator cend = sym.callers.end();

		counts_t c;
		if (global_percent)
			c.total = counts.total;
		else
			c.total = sym.total_caller_count;

		for (cit = sym.callers.begin(); cit != cend; ++cit) {
			out << child_parent_prefix;
			do_output(out, *cit, cit->sample, c);
		}

		do_output(out, sym, sym.sample, counts);

		c = counts_t();
		if (global_percent)
			c.total = counts.total;
		else
			c.total = sym.total_callee_count;

		cend = sym.callees.end();

		for (cit = sym.callees.begin(); cit != cend; ++cit) {
			out << child_parent_prefix;
			do_output(out, *cit, cit->sample, c);
		}

		out << string(79, '-') << endl;
	}
}


diff_formatter::diff_formatter(diff_container const & profile)
{
	counts.total = profile.samples_count();
}


void diff_formatter::output(ostream & out, diff_collection const & syms)
{
	output_header(out);

	diff_collection::const_iterator it = syms.begin();
	diff_collection::const_iterator end = syms.end();
	for (; it != end; ++it)
		do_output(out, *it, it->sample, counts, it->diffs);
}


} // namespace format_output
