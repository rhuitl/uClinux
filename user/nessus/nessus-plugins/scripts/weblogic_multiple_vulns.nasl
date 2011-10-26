#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14722);
 script_cve_id("CVE-2004-2320");
 script_bugtraq_id(11168);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "WebLogic < 8.1 SP3 Multiple Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server is affected by multiple flaws.

Description :

According to its banner, the remote web server is BEA WebLogic version
8.1 SP2 or older.  There are multiple vulnerabilities in such versions
that may allow unautorized access on the remote host or to get the
content of the remote JSP scripts. 

See also : 

http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-65.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-66.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-67.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-68.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-69.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-70.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-71.00.jsp
http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04-72.00.jsp

Solution : 

Apply Service Pack 3 on WebLogic 8.1.

Risk factor : 

Low / CVSS Base Score : 3 
(AV:R/AC:L/Au:NR/C:C/A:N/I:N/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebLogic";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

banner = get_http_banner(port:port);
if (!banner || "WebLogic " >!< banner) exit(0);

pat = "^Server:.*WebLogic .*([0-9]+\.[0-9.]+) ";
matches = egrep(pattern:pat, string:banner);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      # Extract the version and service pack numbers.
      nums = split(ver[1], sep:".", keep:FALSE);
      ver_maj = int(nums[0]);
      ver_min = int(nums[1]);

      sp = ereg_replace(
        string:match, 
        pattern:".* (Service Pack |SP)([0-9]+) .+",
        replace:"\2"
      );
      if (!sp) sp = 0;
      else sp = int(sp);

      # Check them against vulnerable versions listed in BEA's advisories.
      if (
        # version 6.x
        (
          ver_maj == 6 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 6)
          )
        ) ||

        # version 7.x
        (ver_maj == 7 && (ver_min == 0 && sp <= 5)) ||
  
        # version 8.x
        (
          ver_maj == 8 && 
          (
            ver_min < 1 ||
            (ver_min == 1 && sp <= 2)
          )
        )
      ) {
        security_note(port);
      }
      exit(0);
    }
  }
}
