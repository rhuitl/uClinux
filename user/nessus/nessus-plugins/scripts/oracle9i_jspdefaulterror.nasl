#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

 desc["english"] = "
Synopsis :

It is possible to obtain the physical path of the remote server
web root.

Description :

Oracle 9iAS allows remote attackers to obtain the physical path of a file
under the server root via a request for a non-existent .JSP file. The default
error generated leaks the pathname in an error message.

Solution : 

Ensure that virtual paths of URL is different from the actual directory 
path. Also, do not use the <servletzonepath> directory in 
'ApJServMount <servletzonepath> <servletzone>' to store data or files. 

Upgrading to Oracle 9iAS 1.1.2.0.0 will also fix this issue.


See also :

http://otn.oracle.com/deploy/security/pdf/jspexecute_alert.pdf
http://www.kb.cert.org/vuls/id/278971
http://www.cert.org/advisories/CA-2002-08.html

http://www.nextgenss.com/papers/hpoas.pdf 

Risk factor : 

Low";

if(description)
{
 script_id(11226);
 script_bugtraq_id(3341);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2001-1372");
 name["english"] = "Oracle 9iAS default error information disclosure";
 script_name(english:name["english"]);
 

 script_description(english:desc["english"]);
 
 summary["english"] = "Tries to retrieve the phisical path of files through Oracle9iAS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Javier Fernandez-Sanguino");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for the configuration file

     errorjsp = "/nonexistant.jsp";
     req = http_get(item: errorjsp, port: port);
     soc = http_open_socket(port);
     if(soc) {
        send(socket:soc, data:req);
         r = http_recv(socket:soc);
         http_close_socket(soc);
	 location = egrep(pattern:"java.io.FileNotFoundException", string :r);
	 if ( location )  {
 	 # Thanks to Paul Johnston for the tip that made the following line
	 # work (jfs)
         # MA 2005-02-13: This did not work on Windows where / is replaced by \
	     path = ereg_replace(pattern: strcat("(java.io.FileNotFoundException: )(.*[^/\])[/\]+",substr(errorjsp, 1),".*"), replace:"\2", string: location);
	     security_note(port:port, data:desc["english"] + '\n\nPlugin output :\n\n' + string("The web root physical is ", path ));
	 }
     } # if (soc)
}
