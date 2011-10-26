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
 script_id(21461);
 script_version("$Revision: 1.1 $");
 script_cve_id("CVE-2006-1790");
 script_cve_id("CVE-2006-1742");
 script_cve_id("CVE-2006-1741");
 script_cve_id("CVE-2006-1740");
 script_cve_id("CVE-2006-1739");
 script_cve_id("CVE-2006-1738");
 script_cve_id("CVE-2006-1737");
 script_cve_id("CVE-2006-1736");
 script_cve_id("CVE-2006-1735");
 script_cve_id("CVE-2006-1734");
 script_cve_id("CVE-2006-1733");
 script_cve_id("CVE-2006-1732");
 script_cve_id("CVE-2006-1731");
 script_cve_id("CVE-2006-1730");
 script_cve_id("CVE-2006-1729");
 script_cve_id("CVE-2006-1728");
 script_cve_id("CVE-2006-1727");
 script_cve_id("CVE-2006-1726");
 script_cve_id("CVE-2006-1725");
 script_cve_id("CVE-2006-1724");
 script_cve_id("CVE-2006-1723");
 script_cve_id("CVE-2006-1531");
 script_cve_id("CVE-2006-1530");
 script_cve_id("CVE-2006-1529");
 script_cve_id("CVE-2006-1045");
 script_cve_id("CVE-2006-0749");

 script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (695)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: firefox

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for firefox");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"firefox<1.0.8,1",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"firefox>1.5.*,1<1.5.0.2,1",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"linux-firefox<1.5.0.2",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"mozilla<1.7.13,2",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"linux-mozilla<1.7.13",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"seamonkey<1.0.1",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"linux-seamonkey<1.0.1",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"thunderbird<1.5.0.2",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"mozilla-thunderbird<1.5.0.2",
     url:"http://www.FreeBSD.org/ports/portaudit/84630f4a-cd8c-11da-b7b9-000c6ec775d9.html",
     problem:'mozilla -- multiple vulnerabilities',
     seealso:seealso);
