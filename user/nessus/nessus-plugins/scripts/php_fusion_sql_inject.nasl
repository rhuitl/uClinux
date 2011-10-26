#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: r0ut3r
#
#  This script is released under the GNU GPL v2
#
# Fixes by Tenable:
#   - added CVE and additional OSVDB xrefs.
#

if(description)
{
 script_id(15433);
 script_cve_id("CVE-2004-2437", "CVE-2004-2438");
 script_bugtraq_id(11296, 12425);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"10437");
   script_xref(name:"OSVDB", value:"10438");
   script_xref(name:"OSVDB", value:"10439");
 }
 script_version("$Revision: 1.8 $");
 
 name["english"] = "PHP-Fusion members.php SQL injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains several PHP scripts that suffer from
multiple flaws. 

Description :

A vulnerability exists in the remote version of PHP-Fusion that may
allow an attacker to inject arbitrary SQL code and possibly execute
arbitrary code, due to improper validation of user supplied input in the
'rowstart' parameter of script 'members.php'. 

In addition to this, the remote version of this software also contains
an information disclosure vulnerability which may give an attacker more
information about the setup of the remote host. 

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("php_fusion_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/php-fusion");
items = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = items[1];

if ( ereg(pattern:"^([0-3][.,]|4[.,]0[01]([^0-9]|$))", string:version) )
	security_warning(port);
