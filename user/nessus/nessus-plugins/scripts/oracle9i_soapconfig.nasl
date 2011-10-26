#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

if(description)
{
 script_id(11224);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2002-0568");
 script_bugtraq_id(4290);
 script_xref(name:"IAVA", value:"2002-t-0006");
 script_xref(name:"OSVDB", value:"3411");

 name["english"] = "Oracle 9iAS SOAP configuration file retrieval";
 script_name(english:name["english"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS v.1.0.2.2.1, it is possible to
access some configuration files. These file includes detailed
information on how the product was installed in the server
including where the SOAP provider and service manager are located
as well as administrative URLs to access them. They might also
contain sensitive information (usernames and passwords for database
access).

Solution: 
Modify the file permissions so that the web server process
cannot retrieve it. Note however that if the XSQLServlet is present
it might bypass filesystem restrictions.


More information:
http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf
http://www.cert.org/advisories/CA-2002-08.html
http://www.kb.cert.org/vuls/id/476619

Also read:
Hackproofing Oracle Application Server from NGSSoftware:
available at http://www.nextgenss.com/papers/hpoas.pdf 

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tries to retrieve Oracle9iAS SOAP configuration file";
 
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
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for the configuration file

# Note: this plugin can be expanded, I removed the call to 
# SQLConfig since it's already done directly in #10855
 config[0]="/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml";
# config[1]="/xsql/lib/XSQLConfig.xml"; # Already done by plugin #10855

 for(i = 0; config[i] ; i = i+1 ) {
     req = http_get(item:config[i], port:port);
     r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
     if(r == NULL) exit(0);
     if ( "SOAP configuration file" >< r )
	      security_warning(port, data:string("The SOAP configuration file ",config[i]," can be accessed directly :\n" + r));
 } # of the for loop
}
