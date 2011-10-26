#
#	RPM spec file for the Mbedthis AppWeb HTTP web server
#
Summary: Mbedthis AppWeb -- Embeddable HTTP Web Server
Name: appWeb
Version: 1.1.3
Release: 4
Copyright: Dual GPL/commercial
Group: Applications/Internet
Source0: appWeb-1.1.3-4-LINUX-i386.tar.gz
Source1: appWeb-src-1.1.3-4.tar.gz
Source2: appWeb-doc-1.1.3-4.tar.gz
URL: http://www.mbedthis.com/appWeb
Distribution: Mbedthis
Vendor: Mbedthis
BuildRoot: /var/tmp/%{name}-root
AutoReqProv: no

%description
Mbedthis AppWeb is an embeddable HTTP Web Server

%prep
cp $RPM_SOURCE_DIR/../SPECS/binFiles.txt $RPM_BUILD_DIR
cp $RPM_SOURCE_DIR/../SPECS/srcFiles.txt $RPM_BUILD_DIR
cp $RPM_SOURCE_DIR/../SPECS/docFiles.txt $RPM_BUILD_DIR

%build

%install
rm -fr ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}
home=`pwd`
cd ${RPM_BUILD_ROOT}
gzip -dc $RPM_SOURCE_DIR/appWeb-1.1.3-4-LINUX-i386.tar.gz | tar xv

mkdir -p ${RPM_BUILD_ROOT}/usr/src
cd ${RPM_BUILD_ROOT}/usr/src
gzip -dc $RPM_SOURCE_DIR/appWeb-src-1.1.3-4.tar.gz | tar xv
cd ${home}

mkdir -p ${RPM_BUILD_ROOT}/usr/share
cd ${RPM_BUILD_ROOT}/usr/share
gzip -dc $RPM_SOURCE_DIR/appWeb-doc-1.1.3-4.tar.gz | tar xv
cd ${home}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf "$RPM_BUILD_ROOT"

%files -f binFiles.txt

%post
rm -f /var/log/appWeb
ln -s /etc/appWeb/logs /var/log/appWeb
chmod 700 /etc/appWeb/logs 

%preun

%postun

#
#	Source package
#
%package src
Summary: Mbedthis AppWeb -- Source code for Mbedthis AppWeb
Group: Applications/Internet
Prefix: /usr/share/appWeb-1.1.3

%description src
Source code for the Mbedthis AppWeb is an embedded HTTP web server.

%files src -f srcFiles.txt

#
#	Documentation and Samples package
#
%package doc
Summary: Mbedthis AppWeb -- Documentation and Samples for Mbedthis AppWeb
Group: Applications/Internet
Prefix: /usr/share/appWeb-1.1.3

%description doc
Documentation and samples for the Mbedthis AppWeb embedded HTTP web server.

%files doc -f docFiles.txt
