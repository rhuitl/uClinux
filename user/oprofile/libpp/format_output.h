/**
 * @file format_output.h
 * outputting format for symbol lists
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 * @author John Levon
 */

#ifndef FORMAT_OUTPUT_H
#define FORMAT_OUTPUT_H

#include "config.h"

#include <string>
#include <map>
#include <iosfwd>

#include "format_flags.h"
#include "symbol.h"

class symbol_entry;
class sample_entry;
class callgraph_container;
class profile_container;
class diff_container;

namespace format_output {

/// base class for formatter, handle common options to formatter
class formatter {
public:
	formatter();
	virtual ~formatter();

	/// add a given column
	void add_format(format_flags flag);

	/// set the need_header boolean to false
	void show_header(bool);
	/// format for 64 bit wide VMAs
	void vma_format_64bit(bool);
	/// show long (full path) filenames
	void show_long_filenames(bool);
	/// use global count rather symbol count for details percent
	void show_global_percent(bool);

	/**
	 * Set the number of collected profile classes. Each class
	 * will output sample count and percentage in extra columns.
	 *
	 * This class assumes that the profile information has been
	 * populated with the right number of classes.
	 */
	void set_nr_classes(size_t nr_classes);

	/// output table header, implemented by calling the virtual function
	/// output_header_field()
	void output_header(std::ostream & out);

protected:
	struct counts_t {
		/// total sample count
		count_array_t total;
		/// samples so far
		count_array_t cumulated_samples;
		/// percentage so far
		count_array_t cumulated_percent;
		/// detailed percentage so far
		count_array_t cumulated_percent_details;
	};

	/// data passed for output
	struct field_datum {
		field_datum(symbol_entry const & sym,
		            sample_entry const & s,
			    size_t pc, counts_t & c, double d = 0.0)
			: symbol(sym), sample(s), pclass(pc),
			  counts(c), diff(d) {}
		symbol_entry const & symbol;
		sample_entry const & sample;
		size_t pclass;
		mutable counts_t & counts;
		double diff;
	};
 
	/// format callback type
	typedef std::string (formatter::*fct_format)(field_datum const &);
 
	/** @name format functions.
	 * The set of formatting functions, used internally by output().
	 */
	//@{
	std::string format_vma(field_datum const &);
	std::string format_symb_name(field_datum const &);
	std::string format_image_name(field_datum const &);
	std::string format_app_name(field_datum const &);
	std::string format_linenr_info(field_datum const &);
	std::string format_nr_samples(field_datum const &);
	std::string format_nr_cumulated_samples(field_datum const &);
	std::string format_percent(field_datum const &);
	std::string format_cumulated_percent(field_datum const &);
	std::string format_percent_details(field_datum const &);
	std::string format_cumulated_percent_details(field_datum const &);
	std::string format_diff(field_datum const &);
	//@}
 
	/// decribe one field of the colummned output.
	struct field_description {
		field_description() {}
		field_description(std::size_t w, std::string h, fct_format f)
			: width(w), header_name(h), formatter(f) {}
 
		std::size_t width;
		std::string header_name;
		fct_format formatter;
	};
 
	typedef std::map<format_flags, field_description> format_map_t;

	/// actually do output
	void do_output(std::ostream & out, symbol_entry const & symbol,
		      sample_entry const & sample, counts_t & c,
	              diff_array_t const & = diff_array_t(),
	              bool hide_immutable_field = false);
 
	/// returns the nr of char needed to pad this field
	size_t output_header_field(std::ostream & out, format_flags fl,
	                           size_t padding);

	/// returns the nr of char needed to pad this field
	size_t output_field(std::ostream & out, field_datum const & datum,
			   format_flags fl, size_t padding,
			   bool hide_immutable);
 
	/// stores functors for doing actual formatting
	format_map_t format_map;

	/// number of profile classes
	size_t nr_classes;

	/// total counts
	counts_t counts;

	/// formatting flags set
	format_flags flags;
	/// true if we need to format as 64 bits quantities
	bool vma_64;
	/// false if we use basename(filename) in output rather filename
	bool long_filenames;
	/// true if we need to show header before the first output
	bool need_header;
	/// bool if details percentage are relative to total count rather to
	/// symbol count
	bool global_percent;
};
 

/// class to output in a columned format symbols and associated samples
class opreport_formatter : public formatter {
public:
	/// build a ready to use formatter
	opreport_formatter(profile_container const & profile);

	/** output a vector of symbols to out according to the output format
	 * specifier previously set by call(s) to add_format() */
	void output(std::ostream & out, symbol_collection const & syms);

	/// set the output_details boolean
	void show_details(bool);

private:
 
	/** output one symbol symb to out according to the output format
	 * specifier previously set by call(s) to add_format() */
	void output(std::ostream & out, symbol_entry const * symb);

	/// output details for the symbol
	void output_details(std::ostream & out, symbol_entry const * symb);
 
	/// container we work from
	profile_container const & profile;
 
	/// true if we need to show details for each symbols
	bool need_details;
};


/// class to output in a columned format caller/callee and associated samples
class cg_formatter : public formatter {
public:
	/// build a ready to use formatter
	cg_formatter(callgraph_container const & profile);

	/** output callgraph information according to the previously format
	 * specifier set by call(s) to add_format() */
	void output(std::ostream & out, cg_collection const & syms);
};

/// class to output a columned format symbols plus diff values
class diff_formatter : public formatter {
public:
	/// build a ready to use formatter
	diff_formatter(diff_container const & profile);

	/**
	 * Output a vector of symbols to out according to the output
	 * format specifier previously set by call(s) to add_format()
	 */
	void output(std::ostream & out, diff_collection const & syms);

private:
	/// output a single symbol
	void output(std::ostream & out, diff_symbol const & sym);

};

} // namespace format_output 

#endif /* !FORMAT_OUTPUT_H */
