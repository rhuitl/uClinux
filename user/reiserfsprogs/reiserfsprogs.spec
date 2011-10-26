Vendor:       Hans Reiser
Distribution: Hans Reiser
Name:         reiserfsprogs
Release:      1
Copyright:    2001 Hans Reiser
Group:        Unsorted

Packager:     anthon@mnt.org

Version:      3.x.0j
Summary:      utilities belonging to the Reiser filesystem
Source:       reiserfsprogs-%{version}.tar.gz
BuildRoot:    /var/tmp/rpm-reiserfsprogs
%description

The reiserfsprogs package contains programs for creating (mkreiserfs),
checking and correcting any inconsistencies (reiserfsck) and resizing
(resize_reiserfs) of a reiserfs filesystem.

Authors:
--------
Hans Reiser <reiser@namesys.com>
Vitaly Fertman <vetalf@inbox.ru>
Alexander Zarochentcev <zam@namesys.com>
Vladimir Saveliev <vs@namesys.botik.ru>

%prep
%setup -q
# %patch
%build
  MANDIR=$(dirname $(dirname $(man -w fsck | cut -d ' ' -f 1)))
  ./configure --prefix="" --mandir=$MANDIR
  make all
%install
    mkdir -p $RPM_BUILD_ROOT/sbin
    make DESTDIR=$RPM_BUILD_ROOT install
# do we need this?
    cd $RPM_BUILD_ROOT/sbin
    ln -sf reiserfsck fsck.reiserfs

# __os_install_post is normally executed after %install disable it
%define ___build_post %{nil} 
# explicitly call it now, so manpages get compressed, exec's stripped etc.
%{?__os_install_post}
%define __os_install_post %{nil}
# now we have all the files execpt for docs, but their owner is unimportant
cd $RPM_BUILD_ROOT

rm -f rpm-filelist
# we do not have special directories to make
#find . -type d \
# | sed '1,2d;s,^\.,\%attr(-\,root\,root) \%dir ,' >> rpm-filelist
find . -type f \
 | sed 's,^\.,\%attr(-\,root\,root) ,' | fgrep -v rpm-filelist >> rpm-filelist
find . -type l \
 | sed 's,^\.,\%attr(-\,root\,root) ,' >> rpm-filelist

%clean
# in case some overrides buildroot with / don't remove the whole tree
    rm -rf /var/tmp/rpm-reiserfsprogs
%files -f /var/tmp/rpm-reiserfsprogs/rpm-filelist
%doc README
