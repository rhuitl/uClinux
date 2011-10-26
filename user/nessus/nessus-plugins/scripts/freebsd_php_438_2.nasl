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
 script_id(15493);
 script_version("$Revision: 1.3 $");

 script_name(english:"FreeBSD : php -- php_variables memory disclosure (145)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: mod_php4-twig

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for mod_php4-twig");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"mod_php4-twig<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php4-cgi<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php4-cli<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php4-dtc<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php4-horde<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php4-nms<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php4<=4.3.8_2",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"mod_php>=4<=4.3.8_2,1",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"mod_php4>=4<=4.3.8_2,1",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php5<=5.0.1",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php5-cgi<=5.0.1",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"php5-cli<=5.0.1",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);

pkg_test(pkg:"mod_php5<=5.0.1,1",
     url:"http://www.FreeBSD.org/ports/portaudit/ad74a1bd-16d2-11d9-bc4a-000c41e2cdad.html",
     problem:'php -- php_variables memory disclosure',
     seealso:seealso);
