#
#	RPM spec file for the Mbedthis AppWeb HTTP web server
#
Summary: Mbedthis AppWeb -- Embeddable HTTP Web Server
Name: appWeb
Version: !!BLD_VERSION!!
Release: !!BLD_NUMBER!!
Copyright: Dual GPL/commercial
Group: Applications/Internet
Source0: appWeb-!!BLD_VERSION!!-!!BLD_NUMBER!!-!!BLD_OS!!-i386.tar.gz
Source1: appWeb-src-!!BLD_VERSION!!-!!BLD_NUMBER!!.tar.gz
Source2: appWeb-doc-!!BLD_VERSION!!-!!BLD_NUMBER!!.tar.gz
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
gzip -dc $RPM_SOURCE_DIR/appWeb-!!BLD_VERSION!!-!!BLD_NUMBER!!-LINUX-i386.tar.gz | tar xv

mkdir -p ${RPM_BUILD_ROOT}/usr/src
cd ${RPM_BUILD_ROOT}/usr/src
gzip -dc $RPM_SOURCE_DIR/appWeb-src-!!BLD_VERSION!!-!!BLD_NUMBER!!.tar.gz | tar xv
cd ${home}

mkdir -p ${RPM_BUILD_ROOT}/usr/share
cd ${RPM_BUILD_ROOT}/usr/share
gzip -dc $RPM_SOURCE_DIR/appWeb-doc-!!BLD_VERSION!!-!!BLD_NUMBER!!.tar.gz | tar xv
cd ${home}

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf "$RPM_BUILD_ROOT"

%files -f binFiles.txt

%post
rm -f /var/log/appWeb
ln -s !!BLD_PREFIX!!/logs /var/log/appWeb
chmod 700 !!BLD_PREFIX!!/logs 

%preun

%postun

#
#	Source package
#
%package src
Summary: Mbedthis AppWeb -- Source code for Mbedthis AppWeb
Group: Applications/Internet
Prefix: !!BLD_SRC_PREFIX!!

%description src
Source code for the Mbedthis AppWeb is an embedded HTTP web server.

%files src -f srcFiles.txt

#
#	Documentation and Samples package
#
%package doc
Summary: Mbedthis AppWeb -- Documentation and Samples for Mbedthis AppWeb
Group: Applications/Internet
Prefix: !!BLD_DOC_PREFIX!!

%description doc
Documentation and samples for the Mbedthis AppWeb embedded HTTP web server.

%files doc -f docFiles.txt
