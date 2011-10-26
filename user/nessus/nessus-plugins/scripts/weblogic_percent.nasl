#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# Licence : GPL v2
#

 desc["english"] = "
Synopsis :

It is possible to obtain the list of the contents of arbitrary directories
hosted on the remote server.

Description :

Requesting a URL with '%00', '%2e', '%2f' or '%5c' appended to it
makes some WebLogic servers dump the listing of the page 
directory, thus showing potentially sensitive files.

An attacker may also use this flaw to view
the source code of JSP files, or other dynamic content.

Solution : 

Upgrade to WebLogic 6.0 with Service Pack 1 or newer

Risk factor :

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:C)";

if(description)
{
 script_id(10698);
 script_bugtraq_id(2513);
 script_version ("$Revision: 1.22 $");
 name["english"] = "WebLogic Server /%00/ bug";
 name["francais"] = "WebLogic Server /%00/ bug";
 
 script_name(english:name["english"], francais:name["francais"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Make a request like http://www.example.com/%00/";
 summary["francais"] = "Fait une requête du type http://www.example.com/%00/";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 StrongHoldNet",
		francais:"Ce script est Copyright (C) 2001 StrongHoldNet");
 family["english"] = "Remote file access";
 family["francais"] = "Accès aux fichiers distants";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

function http_getdirlist(itemstr, port) {
 buffer = http_get(item:itemstr, port:port);
 rbuf   = http_keepalive_send_recv(port:port, data:buffer);
 if (! rbuf ) exit(0);
 data = tolower(rbuf);
 debug_print(level: 2, 'Answer to GET ', itemstr, ' on port ', port, ': ', rbuf);
  if(("directory listing of" >< data) || ("index of" >< data))
  {
   report = desc["english"] + '\n\nPlugin output :\n\nIt was possible to list / :\n' + data;
   if(strlen(itemstr) > 1) security_warning(port:port, data:report);
   # If itemstr = / we exit the test to avoid FP.
   exit(0);
  }
}

port = get_http_port(default:80);

if(get_port_state(port))
{
  http_getdirlist(itemstr:"/", port:port);	# Anti FP
  http_getdirlist(itemstr:"/%2e/", port:port);
  http_getdirlist(itemstr:"/%2f/", port:port);
  http_getdirlist(itemstr:"/%5c/", port:port);
  http_getdirlist(itemstr:"/%00/", port:port);
}
