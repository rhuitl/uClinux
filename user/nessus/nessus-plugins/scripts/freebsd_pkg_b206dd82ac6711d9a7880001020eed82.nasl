#
# (C) Tenable Network Security
#
# This script contains information extracted from VuXML :
#
# Copyright 2003-2006 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#   copyright notice, this list of conditions and the following
#   disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#   published online in any format, converted to PDF, PostScript,
#   RTF and other formats) must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer
#   in the documentation and/or other materials provided with the
#   distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#
 seealso  = '\n';

if ( description )
{
 script_id(19084);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(13092);
 script_cve_id("CVE-2005-0941");

 script_name(english:"FreeBSD : openoffice -- DOC document heap overflow vulnerability (486)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: ar-openoffice

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for ar-openoffice");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ar-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ar-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ca-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ca-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"cs-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"cs-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"de-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"de-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"dk-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"dk-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"el-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"el-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"es-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"es-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"et-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"et-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"fi-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"fi-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"fr-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"fr-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"gr-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"gr-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"hu-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"hu-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"it-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"it-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ja-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ja-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ko-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ko-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"nl-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"nl-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"pl-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"pl-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"pt-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"pt-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"pt_BR-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"pt_BR-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ru-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ru-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"se-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"se-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"sk-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"sk-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"sl-openoffice-SI<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"sl-openoffice-SI>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"tr-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"tr-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh-openoffice-CN<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh-openoffice-CN>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh-openoffice-TW<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh-openoffice-TW>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"jp-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"jp-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"kr-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"kr-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"sl-openoffice-SL<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"sl-openoffice-SL>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh_TW-openoffice<1.1.4_2",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"zh_TW-openoffice>2.*<=2.0.20050406",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"openoffice>=6.0.a609<=6.0.a638",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"openoffice>=641c<=645",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"openoffice=1.1RC4",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"openoffice=1.1rc5",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ja-openoffice>=6.0.a609<=6.0.a638",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ja-openoffice>=641c<=645",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ja-openoffice=1.1RC4",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);

pkg_test(pkg:"ja-openoffice=1.1rc5",
     url:"http://www.FreeBSD.org/ports/portaudit/b206dd82-ac67-11d9-a788-0001020eed82.html",
     problem:'openoffice -- DOC document heap overflow vulnerability',
     seealso:seealso);
