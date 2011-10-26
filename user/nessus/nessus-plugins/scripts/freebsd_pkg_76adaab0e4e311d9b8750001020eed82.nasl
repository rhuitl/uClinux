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
 script_id(18986);
 script_version("$Revision: 1.4 $");
 script_bugtraq_id(13567);
 script_bugtraq_id(13504);
 script_bugtraq_id(13391);
 script_cve_id("CVE-2005-1470");
 script_cve_id("CVE-2005-1469");
 script_cve_id("CVE-2005-1468");
 script_cve_id("CVE-2005-1467");
 script_cve_id("CVE-2005-1466");
 script_cve_id("CVE-2005-1465");
 script_cve_id("CVE-2005-1464");
 script_cve_id("CVE-2005-1463");
 script_cve_id("CVE-2005-1462");
 script_cve_id("CVE-2005-1461");
 script_cve_id("CVE-2005-1460");
 script_cve_id("CVE-2005-1459");
 script_cve_id("CVE-2005-1458");
 script_cve_id("CVE-2005-1457");
 script_cve_id("CVE-2005-1456");
 script_cve_id("CVE-2005-1281");

 script_name(english:"FreeBSD : ethereal -- multiple protocol dissectors vulnerabilities (299)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: ethereal-lite

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for ethereal-lite");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"ethereal>=0.8.14<0.10.11",
     url:"http://www.FreeBSD.org/ports/portaudit/76adaab0-e4e3-11d9-b875-0001020eed82.html",
     problem:'ethereal -- multiple protocol dissectors vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"ethereal-lite>=0.8.14<0.10.11",
     url:"http://www.FreeBSD.org/ports/portaudit/76adaab0-e4e3-11d9-b875-0001020eed82.html",
     problem:'ethereal -- multiple protocol dissectors vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"tethereal>=0.8.14<0.10.11",
     url:"http://www.FreeBSD.org/ports/portaudit/76adaab0-e4e3-11d9-b875-0001020eed82.html",
     problem:'ethereal -- multiple protocol dissectors vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"tethereal-lite>=0.8.14<0.10.11",
     url:"http://www.FreeBSD.org/ports/portaudit/76adaab0-e4e3-11d9-b875-0001020eed82.html",
     problem:'ethereal -- multiple protocol dissectors vulnerabilities',
     seealso:seealso);
