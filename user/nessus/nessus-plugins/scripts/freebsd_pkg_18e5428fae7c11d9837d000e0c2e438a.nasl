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
 script_id(18852);
 script_version("$Revision: 1.6 $");
 script_cve_id("CVE-2005-1080");

 script_name(english:"FreeBSD : jdk -- jar directory traversal vulnerability (281)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: diablo-jdk-freebsd6

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for diablo-jdk-freebsd6");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"jdk<=1.2.2p11_3",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"jdk>=1.3.*<=1.3.1p9_4",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"jdk>=1.4.*<=1.4.2p7",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"jdk>=1.5.*<=1.5.0p1_1",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"linux-ibm-jdk<=1.4.2_1",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"linux-sun-jdk<=1.4.2.08_1",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"linux-sun-jdk>=1.5.*<=1.5.2.02,2",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"linux-blackdown-jdk<=1.4.2_2",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"diablo-jdk<=1.3.1.0_1",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);

pkg_test(pkg:"diablo-jdk-freebsd6<=i386.1.5.0.07.00",
     url:"http://www.FreeBSD.org/ports/portaudit/18e5428f-ae7c-11d9-837d-000e0c2e438a.html",
     problem:'jdk -- jar directory traversal vulnerability',
     seealso:seealso);
