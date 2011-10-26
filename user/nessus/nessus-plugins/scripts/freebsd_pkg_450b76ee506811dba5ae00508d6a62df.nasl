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
 script_id(22489);
 script_version("$Revision: 1.2 $");
 script_cve_id("CVE-2006-5099");
 script_cve_id("CVE-2006-5098");

 script_name(english:"FreeBSD : dokuwiki -- multiple vulnerabilities (843)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: dokuwiki-devel

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for dokuwiki-devel");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"dokuwiki<20060309_5",
     url:"http://www.FreeBSD.org/ports/portaudit/450b76ee-5068-11db-a5ae-00508d6a62df.html",
     problem:'dokuwiki -- multiple vulnerabilities',
     seealso:seealso);

pkg_test(pkg:"dokuwiki-devel<20060609_2",
     url:"http://www.FreeBSD.org/ports/portaudit/450b76ee-5068-11db-a5ae-00508d6a62df.html",
     problem:'dokuwiki -- multiple vulnerabilities',
     seealso:seealso);
