Name: tinylogin
Version: 0.80
Release: 1
Group: System/Utilities
Summary: TinyLogin is a tiny suite of utilities for handling logins at the console.
Copyright: GPL
Packager : Erik Andersen <andersen@lineo.com>
Conflicts: getty shadow-utils
Buildroot: /tmp/%{Name}-%{Version}
Source: %{Name}-%{Version}.tar.gz

%Description
TinyLogin is a suite of tiny utilities in a multi-call binary, which
enables your system to handle user authentication, and setting of
passwords. It is a drop-in to works nicely with BusyBox (another
multi-call binary), and makes an excellent addition to any small or
embedded system.

%Prep
%setup -q -n %{Name}-%{Version}

%Build
make

%Install
rm -rf $RPM_BUILD_ROOT
PREFIX=$RPM_BUILD_ROOT make install

%Clean
rm -rf $RPM_BUILD_ROOT

%Files 
%defattr(-,root,root)
/
