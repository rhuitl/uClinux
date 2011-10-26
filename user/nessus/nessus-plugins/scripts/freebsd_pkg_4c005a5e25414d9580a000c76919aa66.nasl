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
 script_id(18929);
 script_version("$Revision: 1.4 $");

 script_name(english:"FreeBSD : fd_set -- bitmap index overflow in multiple applications (373)");


desc["english"] = "
The remote host is missing an update to the system

The following package is affected: 3proxy

Solution : Update the package on the remote host
See also : " + seealso; 
 script_description(english:desc["english"]);
 script_summary(english:"Check for 3proxy");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "FreeBSD Local Security Checks";
 script_family(english:family["english"]);
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/FreeBSD/pkg_info");
 exit(0);
}

include('freebsd_package.inc');


pkg_test(pkg:"gatekeeper<2.2.1",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"citadel<6.29",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"3proxy<0.5.b",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"jabber<1.4.3.1_1,1",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"jabber=1.4.4",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"bnc<2.9.3",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"rinetd<0.62_1",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"dante<1.1.15",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);

pkg_test(pkg:"bld<0.3.3",
     url:"http://www.FreeBSD.org/ports/portaudit/4c005a5e-2541-4d95-80a0-00c76919aa66.html",
     problem:'fd_set -- bitmap index overflow in multiple applications',
     seealso:seealso);
