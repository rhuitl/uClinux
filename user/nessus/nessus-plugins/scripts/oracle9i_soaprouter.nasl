#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#
# References:
# http://otn.oracle.com/deploy/security/pdf/ias_soap_alert.pdf
#
# Also relevant:
# VU#476619
# CERT's CA-2002-08
#

if(description)
{
 script_id(11227);
 script_bugtraq_id(4289);
 script_version("$Revision: 1.5 $");
 script_cve_id("CVE-2001-1371");
 name["english"] = "Oracle 9iAS SOAP Default Configuration Vulnerability ";
 script_name(english:name["english"]);
 
 desc["english"] = "
In a default installation of Oracle 9iAS v.1.0.2.2, it is possible to
deploy or undeploy SOAP services without the need of any kind of credentials.
This is due to SOAP being enabled by default after installation in order to 
provide a convenient way to use SOAP samples. However, this feature poses a 
threat to HTTP servers with public access since remote attackers can create
soap services and then invoke them remotely. Since SOAP services can
contain arbitrary Java code in Oracle 9iAS this means that an attacker
can execute arbitray code in the remote server.

Solution: 
Disable SOAP or the deploy/undeploy feature by editing
$ORACLE_HOME/Apache/Jserver/etc/jserv.conf and removing/commenting
the following four lines:
ApJServGroup group2 1 1 $ORACLE_HOME/Apache/Jserv/etc/jservSoap.properties
ApJServMount /soap/servlet ajpv12://localhost:8200/soap
ApJServMount /dms2 ajpv12://localhost:8200/soap
ApJServGroupMount /soap/servlet balance://group2/soap

Note that the port number might be different from  8200.
Also, you will need to change in the file 
$ORACLE_HOME/soap/werbapps/soap/WEB-INF/config/soapConfig.xml:
<osc:option name='autoDeploy' value='true' />
to
<osc:option name='autoDeploy' value='false' />



More information:
http://otn.oracle.com/deploy/security/pdf/ias_soap_alert.pdf
http://www.cert.org/advisories/CA-2002-08.html
http://www.kb.cert.org/vuls/id/476619

Also read:
Hackproofing Oracle Application Server from NGSSoftware:
available at http://www.nextgenss.com/papers/hpoas.pdf 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for Oracle9iAS default SOAP installation";
 
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
# Make a request for /soap/servlet/soaprouter

 req = http_get(item:"/soap/servlet/soaprouter", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("SOAP Server" >< r)	
 	security_hole(port);

 }
}
