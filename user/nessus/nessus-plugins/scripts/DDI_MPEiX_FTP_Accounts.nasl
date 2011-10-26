#
# This script was written by H D Moore <hdmoore@digitaldefense.net>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11000); 
 script_version ("$Revision: 1.6 $");  
 script_cve_id("CVE-1999-0502");
 name["english"] = "MPEi/X Default Accounts";

 script_name(english:name["english"]);
 
 desc["english"] = "
This host has one or more accounts with a blank 
password.  Please see the data section for a list 
of these accounts.

Solution: Apply complex passwords to all accounts.

Risk factor : High
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for open accounts";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 H D Moore");
 family["english"] = "Backdoors";

 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_exclude_keys("ftp/JetDirect");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

#
# default account listing
#
accounts[0] = "OPERATOR.SYS";
accounts[1] = "MANAGER.SYS";
accounts[2] = "SPECTRUM.CU1";
accounts[3] = "CU1.DBA";
accounts[4] = "CU1.MANAGER";
accounts[5] = "CU1.MGR";
accounts[6] = "CUTEST1.MANAGER";
accounts[7] = "CUTEST1.MGR";
accounts[8] = "CUTRAIN.MANAGER";
accounts[9] = "CUTRAIN.MGR";
accounts[10] = "SUPPORT.FIELD";
accounts[11] = "SUPPORT.MANAGER";
accounts[12] = "SUPPORT.MGR";
accounts[13] = "SUPPORT.OPERATOR";
accounts[14] = "SYS.MANAGER";
accounts[15] = "SYS.MGR";
accounts[16] = "SYS.NWIXUSER";
accounts[17] = "SYS.OPERATOR";
accounts[18] = "SYS.PCUSER";
accounts[19] = "SYS.RSBCMON";
accounts[20] = "SYSMGR.MANAGER";
accounts[21] = "SYSMGR.MGR";
accounts[22] = "TELAMON.MANAGER";
accounts[23] = "TELAMON.MGR";
accounts[24] = "TELESUP.FIELD";
accounts[25] = "TELESUP.MAIL";
accounts[26] = "TELESUP.MANAGER";
accounts[27] = "TELESUP.MGR";
accounts[28] = "VECSL.MANAGER";
accounts[29] = "VECSL.MGR";
accounts[30] = "VESOFT.MANAGER";
accounts[31] = "VESOFT.MGR";
accounts[32] = "BIND.MANAGER";
accounts[33] = "BIND.MGR";
accounts[34] = "CAROLIAN.MANAGER";
accounts[35] = "CAROLIAN.MGR";
accounts[36] = "CCC.MANAGER";
accounts[37] = "CCC.MGR";
accounts[38] = "CCC.SPOOL";
accounts[39] = "CNAS.MGR";
accounts[40] = "COGNOS.MANAGER";
accounts[41] = "COGNOS.MGR";
accounts[42] = "COGNOS.OPERATOR";
accounts[43] = "CONV.MANAGER";
accounts[44] = "CONV.MGR";
accounts[45] = "HPLANMANAGER.MANAGER";
accounts[46] = "HPLANMANAGER.MGR";
accounts[47] = "HPNCS.FIELD";
accounts[48] = "HPNCS.MANAGER";
accounts[49] = "HPNCS.MGR";
accounts[50] = "HPOFFICE.ADVMAIL";
accounts[51] = "HPOFFICE.DESKMON";
accounts[52] = "HPOFFICE.MAIL";
accounts[53] = "HPOFFICE.MAILMAN";
accounts[54] = "HPOFFICE.MAILROOM";
accounts[55] = "HPOFFICE.MAILTRCK";
accounts[56] = "HPOFFICE.MANAGER";
accounts[57] = "HPOFFICE.MGR";
accounts[58] = "HPOFFICE.OPENMAIL";
accounts[59] = "HPOFFICE.PCUSER";
accounts[60] = "HPOFFICE.SPOOLMAN";
accounts[61] = "HPOFFICE.WP";
accounts[62] = "HPOFFICE.X400FER";
accounts[63] = "HPOPTMGT.MANAGER";
accounts[64] = "HPOPTMGT.MGR";
accounts[65] = "HPPL85.FIELD";
accounts[66] = "HPPL85.MANAGER";
accounts[67] = "HPPL85.MGR";
accounts[68] = "HPPL87.FIELD";
accounts[69] = "HPPL87.MANAGER";
accounts[70] = "HPPL87.MGR";
accounts[71] = "HPPL89.FIELD";
accounts[72] = "HPPL89.MANAGER";
accounts[73] = "HPPL89.MGR";
accounts[74] = "HPSKTS.MANAGER";
accounts[75] = "HPSKTS.MGR";
accounts[76] = "HPWORD.MANAGER";
accounts[77] = "HPWORD.MGR";
accounts[78] = "INFOSYS.MANAGER";
accounts[79] = "INFOSYS.MGR";
accounts[80] = "ITF3000.MANAGER";
accounts[81] = "ITF3000.MGR";
accounts[82] = "JAVA.MANAGER";
accounts[83] = "JAVA.MGR";
accounts[84] = "RJE.MANAGER";
accounts[85] = "RJE.MGR";
accounts[86] = "ROBELLE.MANAGER";
accounts[87] = "ROBELLE.MGR";
accounts[88] = "SNADS.MANAGER";
accounts[89] = "SNADS.MGR";

#
# The script code starts here
#


# exit if this is a JetDirect
JD = get_kb_item("ftp/JetDirect");
if (JD)exit(0);

# open the connection
port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port:port);

# check for HP ftp service
if("HP ARPA FTP" >< banner)
{
    # do nothing
} else {
    exit(0);
}

soc = open_sock_tcp(port);
if(!soc)exit(0);
d = ftp_recv_line(socket:soc);

CRLF = raw_string(0x0d, 0x0a);
cracked = string("");

for(i=0; accounts[i]; i = i +1)
{
    username = accounts[i];
    user = string("USER ", username, CRLF); 
    
    send(socket:soc, data:user);
    resp = ftp_recv_line(socket:soc);
    
    if ("230 User logged on" >< resp)
    {
        cracked = string(cracked, username, "\n");
    }
}
ftp_close(socket:soc);

if (strlen(cracked))
{
    report = string("These accounts have no passwords:\n\n", cracked);
    security_hole(port:port, data:report);
}


