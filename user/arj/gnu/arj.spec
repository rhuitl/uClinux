Summary: Free and portable clone of the ARJ archiver
Name: arj
Version: 3.10
Release: 1
Copyright: GPL
Group: Applications/Archiving
Source: http://unc.dl.sourceforge.net/sourceforge/arj/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildRequires: autoconf

%description
The arj program is a free clone of the ARJ archiver for DOS and Windows.
It can be used to create and extract archives and uses the save format
as the proprietary version.

Install the arj package if you need to uncompress and create .arj format
archives.

%prep
%setup -q -n arj

%build
cd gnu
autoconf
./configure
cd ..
make prepare RPM_OPT_FLAGS="$RPM_OPT_FLAGS"
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin

install -m 755 linux-gnu/en/rs/arj/arj $RPM_BUILD_ROOT/usr/bin/arj
install -m 755 linux-gnu/en/rs/arjdisp/arjdisp $RPM_BUILD_ROOT/usr/bin/arjdisp
install -m 755 linux-gnu/en/rs/rearj/rearj $RPM_BUILD_ROOT/usr/bin/rearj

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc doc/*

/usr/bin/*

%changelog
* Sun Dec 15 2002 Andrew Belov <andrew_belov@newmail.ru>
- Adapted for the previous naming changes

* Sat Dec 14 2002 Pavel Roskin <proski@gnu.org>
- Initial version

