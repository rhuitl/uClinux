#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# Modified by Paul Johnston for Westpoint Ltd to display the web root
#
# See the Nessus Scripts License for details
#



if(description)
{
 script_id(11393);
 script_bugtraq_id(4542);


 name["english"] = "ColdFusion Path Disclosure";
 script_name(english:name["english"]);


 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2002-0576");
 desc["english"] = "
It is possible to make the remote web server
disclose the physical path to its web root by
requesting a MS-DOS device ending in .dbm (as
in nul.dbm).

Solution :
 The vendor suggests turning on 'Check that file exists' :

   Windows 2000:
   1. Open the Management console
   2. Click on 'Internet Information Services'
   3. Right-click on the website and select 'Properties'
   4. Select 'Home Directory'
   5. Click on 'Configuration'
   6. Select '.cfm'
   7. Click on 'Edit'
   8. Make sure 'Check that file exists' is checked
   9. Do the same for '.dbm'

Risk factor : Low";
 script_description(english:desc["english"]);

 summary["english"] = "Checks for a ColdFusion vulnerability";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

#
# The script code starts here
#

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);

req = http_get(item:"/nul.dbm", port:port);
res = http_keepalive_send_recv(port:port, data:req);

webroot = eregmatch(pattern:"([A-Z]:\\[^<>]+\\)nul.dbm", string:res);
if(!isnull(webroot))
{
  report = "It is possible to make the remote web server
disclose the physical path to its web root by
requesting a MS-DOS device ending in .dbm (as
in nul.dbm).

The remote web root is : " + webroot[1] + "

Solution :
 The vendor suggests turning on 'Check that file exists' :

   Windows 2000:
   1. Open the Management console
   2. Click on 'Internet Information Services'
   3. Right-click on the website and select 'Properties'
   4. Select 'Home Directory'
   5. Click on 'Configuration'
   6. Select '.cfm'
   7. Click on 'Edit'
   8. Make sure 'Check that file exists' is checked
   9. Do the same for '.dbm'

Risk factor : Low";
  security_warning(port:port, data:report);
}
