/**
 * @file file_manip.cpp
 * Useful file management helpers
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Philippe Elie
 * @author John Levon
 */

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <fnmatch.h>
#include <utime.h>

#include <cstdio>
#include <cerrno>
#include <iostream>
#include <fstream>
#include <vector>

#include "op_file.h"

#include "file_manip.h"
#include "string_manip.h"

using namespace std;


bool copy_file(string const & source, string const & destination)
{
	struct stat buf;
	if (stat(source.c_str(), &buf))
		return false;

	int fd = open(destination.c_str(), O_RDWR|O_CREAT);
	if (fd < 0)
		return false;
	close(fd);

	mode_t mode = buf.st_mode & ~S_IFMT;
	if (!(mode & S_IWUSR))
		mode |= S_IWUSR;
	if (chmod(destination.c_str(), mode))
		return false;

	// ignore error here: a simple user can copy a root.root 744 file
	// but can't chown the copied file to root.
	chown(destination.c_str(), buf.st_uid, buf.st_gid);

	ifstream in(source.c_str());
	if (!in)
		return false;
	{
	ofstream out(destination.c_str(), ios::trunc);
	if (!out)
		return false;
	out << in.rdbuf();
	}

	struct utimbuf utim;
	utim.actime = buf.st_atime;
	utim.modtime = buf.st_mtime;
	if (utime(destination.c_str(), &utim))
		return false;

	return true;
}


bool is_directory(string const & dirname)
{
	struct stat st;
	return !stat(dirname.c_str(), &st) && S_ISDIR(st.st_mode);
}


bool is_files_identical(string const & file1, string const & file2)
{
	struct stat st1;
	struct stat st2;

	if (stat(file1.c_str(), &st1) == 0 && stat(file2.c_str(), &st2) == 0) {
		if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino)
			return true;
	}

	return false;
}


string const op_realpath(string const & name)
{
	static char tmp[PATH_MAX];
	if (!realpath(name.c_str(), tmp))
		return name;
	return string(tmp);
}


bool op_file_readable(string const & file)
{
	return op_file_readable(file.c_str());
}

inline static bool is_directory_name(char const * name)
{
	return name[0] == '.' &&
		(name[1] == '\0' ||
		 (name[1] == '.' && name[2] == '\0'));
}


bool create_file_list(list<string> & file_list, string const & base_dir,
		      string const & filter, bool recursive)
{
	DIR * dir;
	struct dirent * ent;

	if (!(dir = opendir(base_dir.c_str())))
		return false;

	while ((ent = readdir(dir)) != 0) {
		if (!is_directory_name(ent->d_name) &&
		    fnmatch(filter.c_str(), ent->d_name, 0) != FNM_NOMATCH) {
			if (recursive) {
				struct stat stat_buffer;
				string name = base_dir + '/' + ent->d_name;
				if (stat(name.c_str(), &stat_buffer) == 0) {
					if (S_ISDIR(stat_buffer.st_mode) &&
					    !S_ISLNK(stat_buffer.st_mode)) {
						// recursive retrieve
						create_file_list(file_list,
								 name, filter,
								 recursive);
					} else {
						file_list.push_back(name);
					}
				}
			} else {
				file_list.push_back(ent->d_name);
			}
		}
	}

	closedir(dir);

	return true;
}


/**
 * @param path_name the path where we remove trailing '/'
 *
 * erase all trailing '/' in path_name except if the last '/' is at pos 0
 */
static string erase_trailing_path_separator(string const & path_name)
{
	string result(path_name);

	while (result.length() > 1) {
		if (result[result.length() - 1] != '/')
			break;
		result.erase(result.length() - 1, 1);
	}

	return result;
}


string op_dirname(string const & file_name)
{
	string result = erase_trailing_path_separator(file_name);
	if (result.find_first_of('/') == string::npos)
		return "."; 	 
  	 
	// catch result == "/" 	 
	if (result.length() == 1) 	 
		return result;

	size_t pos = result.find_last_of('/'); 	 

	// "/usr" must return "/" 	 
	if (pos == 0) 	 
		pos = 1; 	 

	result.erase(pos, result.length() - pos); 	 

	// "////usr" must return "/"
	return erase_trailing_path_separator(result);
}


string op_basename(string const & path_name)
{
	string result = erase_trailing_path_separator(path_name);

	// catch result == "/"
	if (result.length() == 1)
		return result;

	return erase_to_last_of(result, '/');
}
