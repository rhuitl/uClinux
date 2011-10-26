# - Written by Christoff Breytenbach <christoff@sensepost.com>
# - Checks only for passwords on Compaq Web-based / HP System Management
#   Agent on HTTPS (2381/tcp), and not on older versions with login
#   still on HTTP (2301/tcp)
# - Tested on CompaqHTTPServer 4.1, 4.2, 5.0, 5.7

if(description)
{
    script_id(11879);
    script_version ("$Revision: 1.8 $");
    name["english"] = "Compaq Web-based Management Login";
    script_name(english:name["english"]);

    desc["english"] = "
Checks the administrator account on Compaq Web-based Management / HP System Management agents for the default or predictable passwords.
";

    script_description(english:desc["english"]);

    summary["english"] = "Detect Predictable Compaq Web-based Management / HP System Management Agent Administrator Passwords";

    script_summary(english:summary["english"]);

    script_category(ACT_ATTACK);

    script_copyright(english:"This script is Copyright (C) 2004 SensePost");

    family["english"] = "General";
    script_family(english:family["english"]);
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www", 2381);
    exit(0);
}

include("global_settings.inc");
include("http_func.inc");

# Check starts here

function https_get(port, request)
{
    if(get_port_state(port))
    {
         if(port == 2381)soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
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

report = string("The Compaq Web-based Management / HP System Management Agent active on the remote host is configured with the default, or a predictable, administrator password.\n\nDepending on the agents integrated, this allows an attacker to view sensitive and verbose system information, and may even allow more active attacks such as rebooting the remote system. Furthermore, if an SNMP agent is configured on the remote host it may disclose the SNMP community strings in use, allowing an attacker to set device configuration if the 'write' community string is uncovered.\n\nTo manually test for this bug, you can log into the Compaq web server via a browser (https://host:2381/). Log in with a username/password combination of administrator/"); 

solution = string("\n\nSolution: Ensure that all passwords for Compaq Web-based Management / HP System Management Agent accounts are set to stronger, less easily guessable, alternatives. As a further precaution, use the 'IP Restricted Logins' setting to allow only authorised IP's to manage this agent.\n\nRisk factor: High");

passlist = make_list ('administrator', 'admin', 'cim', 'cim7', 'password');

if ( thorough_tests )
 port = get_http_port(default:2381);
else
 port = 2381;

req = string("GET /cpqlogin.htm?RedirectUrl=/&RedirectQueryString= HTTP/1.0\r\n\r\n");

if(debug==1) display(req);

retval = https_get(port:port, request:req);
if(retval == NULL) exit(0);

if(debug == 1) display(retval);

if((retval =~ "HTTP/1.[01] 200") && ("Server: CompaqHTTPServer/" >< retval) && ("Cookie: Compaq" >< retval))
{
    foreach pass (passlist) {
        temp1 = strstr(retval, "Set-Cookie: ");
        temp2 = strstr(temp1, ";");
        cookie = temp1 - temp2;
	if ( ! cookie ) continue;
        cookie = str_replace(string:cookie, find:"Set-Cookie", replace:"Cookie");
        poststr = string("redirecturl=&redirectquerystring=&user=administrator&password=", pass);
        
        req = string("POST /proxy/ssllogin HTTP/1.0\r\n", cookie, 
"\r\nContent-Length: ", strlen(poststr), "\r\n\r\n", poststr, "\r\n");

        if(debug==1) display("\n\n***********************\n\n", req);

        retval = https_get(port:port, request:req);

        if(debug==1) display(retval);

        if("CpqElm-Login: success" >< retval)
        {
            report = report + string(pass, ".") + solution; 
            security_hole(port:port, data:report);
            exit(0);
        }
    }
}
