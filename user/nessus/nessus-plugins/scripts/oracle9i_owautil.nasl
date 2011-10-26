#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

if(description)
{
 script_id(11225);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0006");
 script_bugtraq_id(4294);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-0560");
 name["english"] = "Oracle 9iAS OWA UTIL access";
 script_name(english:name["english"]);
 
 desc["english"] = "
Oracle 9iAS can provide access to the PL/SQL application OWA_UTIL that
provides web access to some stored procedures. These procuedures,
without authentication, can allow users to access sensitive information
such as source code of applications, user credentials to other database
servers and run arbitrary SQL queries on servers accessed by the application
server.

Solution: 
Apply the appropiate patch listed 
in http://otn.oracle.com/deploy/security/pdf/ias_modplsql_alert.pdf
which details how you can restrict unauthenticated access to procedures
using the exclusion_list parameter in the PL/SQL gateway configuration file:
/Apache/modplsql/cfg/wdbsvr.app. 


More information:
http://www.kb.cert.org/vuls/id/307835
http://www.cert.org/advisories/CA-2002-08.html
http://otn.oracle.co.kr/docs/oracle78/was3x/was301/cart/psutil.htm

Also read:
Hackproofing Oracle Application Server from NGSSoftware:
available at http://www.nextgenss.com/papers/hpoas.pdf 

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to access the OWA_UTIL program directly";
 
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
# Make a request for the owa util file

owa[0] = "/ows-bin/owa/owa_util.signature"; # Note: sometimes access to this file seems to return 0 bytes
# The following mutations are derived from
# http://archives.neohapsis.com/archives/ntbugtraq/1999-q4/0023.html 
# and might provide access to it in some cases were it has
# been prevented through authentication
owa[1] = "/ows-bin/owa/owa_util%2esignature";
owa[2] = "/ows-bin/owa/owa%5futil.signature";
owa[3] = "/ows-bin/owa/owa%5futil.signature";
# These are extracted from David Lichtfield's excelent paper:
owa[3] = "/ows-bin/owa/%20owa_util.signature";
owa[4] = "/ows-bin/owa/%0aowa_util.signature";
owa[5] = "/ows-bin/owa/%08owa_util.signature";
# These are some other procedures derived from the same mail
owa[6] = "/ows-bin/owa/owa_util.showsource";
owa[7] = "/ows-bin/owa/owa_util.cellsprint";
owa[8] = "/ows-bin/owa/owa_util.tableprint";
owa[9] = "/ows-bin/owa/owa_util.listprint";
owa[10] = "/ows-bin/owa/owa_util.show_query_columns";
# Note that instead of ows-bin/owa any combination of
# pls/dadname could be used: pls/simpledad, pls/sys...


        for ( i=0; owa[i]; i=i+1 ) {
                req = http_get(item:owa[i], port:port);
		r = http_keepalive_send_recv(port:port, data:req);
                if( r == NULL ) exit(0);
		if ( "This page was produced by the PL/SQL Web ToolKit" >< r || "DAD name:" >< r  || "PATH_INFO=/ows-bin/owa/" >< r )  
				security_hole(port, data:string("Access to OWA_UTIL possible through ", owa[i]));
        } # for i
 
}
