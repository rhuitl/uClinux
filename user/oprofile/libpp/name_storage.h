/**
 * @file name_storage.h
 * Type-safe unique storage of global names (filenames and symbols)
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 * @author John Levon
 */

#ifndef NAME_STORAGE_H
#define NAME_STORAGE_H

#include <string>

#include "unique_storage.h"

/// store original name and processed name
struct stored_name {
	stored_name(std::string const & n = std::string())
		: name(n) {}

	bool operator<(stored_name const & rhs) const {
		return name < rhs.name;
	}

	std::string name;
	mutable std::string name_processed;
};


/// partial specialization for unique storage of names
template <typename I> struct name_storage : unique_storage<I, stored_name> {

	typedef typename unique_storage<I, stored_name>::id_value id_value;

	std::string const & name(id_value const & id) const {
		return unique_storage<I, stored_name>::get(id).name;
	}
};


class debug_name_tag;
/// a debug filename
typedef name_storage<debug_name_tag>::id_value debug_name_id;

/// class storing a set of shared debug name (source filename)
struct debug_name_storage : name_storage<debug_name_tag> {
	/// return the basename for the given ID
	std::string const & basename(debug_name_id id) const;
};


class image_name_tag;
/// an image name
typedef name_storage<image_name_tag>::id_value image_name_id;

/// class storing a set of shared image name
struct image_name_storage : name_storage<image_name_tag> {
	/// return the basename name for the given ID
	std::string const & basename(image_name_id) const;
};


class symbol_name_tag;
/// a (demangled) symbol
typedef name_storage<symbol_name_tag>::id_value symbol_name_id;

/// class storing a set of shared symbol name
struct symbol_name_storage : name_storage<symbol_name_tag> {
	/// return the demangled name for the given ID
	std::string const & demangle(symbol_name_id id) const;
};


/// for images
extern image_name_storage image_names;

/// for debug filenames i.e. source filename
extern debug_name_storage debug_names;

/// for symbols
extern symbol_name_storage symbol_names;


/**
 * debug name specialisation for comparison.
 *
 * We compare by name rather by id since what user will see are
 * filename and when the criteria "samples count" give identical
 * result it's better to obtain result sorted by the user visible
 * property filename rather than by an obscure, invisible from user
 * point of view, file identifier property
 */
template<> inline bool
debug_name_id::operator<(debug_name_id const & rhs) const
{
	return debug_names.name(*this) < debug_names.name(rhs);
}

#endif /* !NAME_STORAGE_H */
