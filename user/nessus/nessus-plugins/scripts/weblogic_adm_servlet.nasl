#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#
# Thanks to Sullo who supplied a sample of WebLogic banners

if(description)
{
 script_id(11486);
 script_cve_id("CVE-2003-1095");
 script_bugtraq_id(7122, 7124, 7130, 7131);
 script_version ("$Revision: 1.7 $");
 
 
 name["english"] = "WebLogic management servlet";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote web server is WebLogic

An internal management servlet which does not properly
check user credential can be accessed from outside, allowing
a cracker to change user passwords, and even upload or download
any file on the remote server.

In addition to this, there is a flaw in WebLogic 7.0 which may 
allow users to delete empty subcontexts.

*** Note that Nessus only checked the version in the server banner
*** So this might be a false positive.

See also : http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-28.jsp

Solutions : 
- apply Service Pack 2 Rolling Patch 3 on WebLogic 6.0
- apply Service Pack 4 on WebLogic 6.1
- apply Service Pack 2 on WebLogic 7.0 or 7.0.0.1

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebLogic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Michel Arboi");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);

if ("WebLogic " >!< banner) exit(0);	 # Not WebLogic

# All those tests below have NEVER been validated!
# Here are the banner we got:
# WebLogic 5.1.0 04/03/2000 17:13:23 #66825
# WebLogic 5.1.0 Service Pack 10 07/11/2001 21:04:48 #126882
# WebLogic 5.1.0 Service Pack 12 04/14/2002 22:57:48 #178459
# WebLogic 5.1.0 Service Pack 6 09/20/2000 21:03:19 #84511
# WebLogic 5.1.0 Service Pack 9 04/06/2001 12:48:33 #105983 - 128 bit domestic version
# WebLogic WebLogic Server 6.1 SP1  09/18/2001 14:28:44 #138716
# WebLogic WebLogic Server 6.1 SP3  06/19/2002 22:25:39 #190835
# WebLogic WebLogic Temporary Patch for CR067505 02/12/2002 17:10:21

# I suppose that this kind of thing might exist
if (" Temporary Patch for CR096950" >< banner) exit(0);

if (banner =~ "WebLogic .* 6\.1 ")
{
  if (" SP4 " >!< banner) security_hole(port);
  exit(0);
}

if (banner =~ "WebLogic .* 6\.0 ")
{
  if (banner !~ " SP[3-9] " && " SP2 RP3 " >!< banner) security_hole(port);
  exit(0);
}

if (banner =~ "WebLogic .* 7\.0(\.0\.1)? ")
{
  if (banner !~ " SP[2-9]") security_hole(port);
  exit(0);
}

