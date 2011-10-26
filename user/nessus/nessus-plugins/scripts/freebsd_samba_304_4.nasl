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
 script_id(13656);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2004-0686");
 script_cve_id("CVE-2004-0600");

 script_name(english:"FreeBSD : Multiple Potential Buffer Overruns in Samba (173)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: ja-samba

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for ja-samba");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"samba>=3.*<3.0.5,1",
     url:"http://www.FreeBSD.org/ports/portaudit/2de14f7a-dad9-11d8-b59a-00061bc2ad93.html",
     problem:'Multiple Potential Buffer Overruns in Samba',
     seealso:seealso);

pkg_test(pkg:"samba<2.2.10",
     url:"http://www.FreeBSD.org/ports/portaudit/2de14f7a-dad9-11d8-b59a-00061bc2ad93.html",
     problem:'Multiple Potential Buffer Overruns in Samba',
     seealso:seealso);

pkg_test(pkg:"ja-samba<2.2.10.*",
     url:"http://www.FreeBSD.org/ports/portaudit/2de14f7a-dad9-11d8-b59a-00061bc2ad93.html",
     problem:'Multiple Potential Buffer Overruns in Samba',
     seealso:seealso);
