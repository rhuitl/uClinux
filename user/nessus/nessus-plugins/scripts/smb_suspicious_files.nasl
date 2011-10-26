#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
# BHO X http://computercops.biz/clsid.php?type=5 update 27012005
#
#
# Tenable grants a special exception for this plugin to use the library 
# 'smb_func.inc'. This exception does not apply to any modified version of 
# this plugin.
#


if(description)
{
 script_id(16314);
 script_version("$Revision: 1.5 $");

 name["english"] = "Potentially unwanted software";

 script_name(english:name["english"]);
 
 desc["english"] = "
This script checks for the presence of files and programs which 
might have been installed without the consent of the user of the
remote host.

Verify each of softwares found to see if they are compliant with
you security policy.
	
Solution : See the URLs which will appear in the report
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of differents dll on the remote host";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak and Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
if ( get_kb_item("SMB/samba") ) exit(0);

global_var handle;


port = kb_smb_transport();
if(!port)exit(0);

if(!get_port_state(port))return(FALSE);
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

soc = open_sock_tcp(port);
if(!soc)exit(0);

session_init(socket:soc, hostname:kb_smb_name());
ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_CLASS_ROOT);
if ( isnull(handle) ) exit(0);


function check_reg(name, url, key, item, exp)
{
  local_var key_h, value, sz;


  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if( ! isnull(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if ( ! isnull(value) ) sz = value[1]; 
    else return 0;
  }
  else return 0;
  
 if(exp == NULL || tolower(exp) >< tolower(sz))
 {
  report = string(
"'", name, "' is installed on the remote host.\n",
"Make sure that the user of the remote host intended to install
this software and that its use matches your corporate security
policy.\n\n",
"Solution : ", url, "\n",
"Risk factor : High");
 
  security_hole(port:kb_smb_transport(), data:report);
 }
}

i = 0;

########################################################################

name = make_list();

name[i]	= "Commonname toolbar";
url[i]	= "http://www.doxdesk.com/parasite/CommonName.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CnbarIE.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msxmlpp.dll";

i++;
name[i]	= "AutoSearch";
url[i]	= "http://www.doxdesk.com/parasite/AutoSearch.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000000001}\InprocServer32";
item[i]	= NULL;
exp[i]	= "safesearch.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000000001}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msxmlfilt.dll";

i++;
name[i]	= "ClearSearch";
url[i]	= "http://doxdesk.com/parasite/ClearSearch.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000000221}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CSIE.DLL";

i++;
name[i]	= "ClearSearch";
url[i]	= "http://doxdesk.com/parasite/ClearSearch.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000000240}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IE_ClrSch.dll";

i++;
name[i]	= "ClearSearch";
url[i]	= "http://doxdesk.com/parasite/ClearSearch.html";
key[i]	= "CLSID\{00000000-0000-0000-0000-000000002230}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Csbb.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-0000-0000-8835-3EFF76BF2657}\InprocServer32";
item[i]	= NULL;
exp[i]	= "kw3eef76.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-0000-0000-BFA1-D7EE6696B865}\InprocServer32";
item[i]	= NULL;
exp[i]	= "icdd7ee6.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-0000-41a3-98CF-00000000168B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wm41a398.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-0000-47c5-A90F-2CDE8F7638DB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iel2cde8.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0000-5DFC-5652-1705043F6518}\InprocServer32";
item[i]	= NULL;
exp[i]	= "audiosrv32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0000-7EBF-57C6-0BAE047EA682}\InprocServer32";
item[i]	= NULL;
exp[i]	= "autodisc32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0001-0345-2280-0287F27A63EE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Browserad.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0001-1DBE-075A-39EC04BD88AF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Avicap32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0001-F7A6-1F38-0204019E355E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Asferror32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0002-53D4-0622-35EA0235778E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ati2dvaa32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0008-D357-0798-004401965D4A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "apphelp32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0009-1C42-7D61-6CFF050894A7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "avisynthEx32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0015-BD9C-263A-493001BA0C6C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "asycfilt32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-002B-EFE6-6B08-560C01922D3B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Apcups32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0033-C1AC-0E62-0C1F0537605D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "aviwrap32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-008C-1E65-6AA6-3A270279F027}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ati2dvag32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-00FA-71ED-4ABA-348801BAA0A9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Athprxy32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-08C8-8E68-587B-61F804EE6164}\InprocServer32";
item[i]	= NULL;
exp[i]	= "avisynth32.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-0C95-B1F8-547A-405204D6961A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "avifile32.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-10D6-4e5f-8F7F-29B32C1C0FC4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "icddefff.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-1530-70F0-6420-4C2701B37263}\InprocServer32";
item[i]	= NULL;
exp[i]	= "asfsipc32.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-167B-41bc-95FF-86A07B14712C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "he3bbcff.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-2565-4c5b-A455-A74C8A2247AB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wmcbaaca.dll";

i++;
name[i]	= "TX 4 BrowserAd adware";
url[i]	= "";
key[i]	= "CLSID\{00000000-387E-9D50-0079-1744044CB22A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "authz32.dll";

i++;
name[i] = "VX2 Respondmiter, Blackstone Transponder";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html";
key[i]	= "CLSID\{00000000-5eb9-11d5-9d45-009027c14662}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ehelper.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{00000000-64C4-4a64-9767-895AB4921E41}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ielcaabe.dll";

i++;
name[i]	= "iMesh";
url[i]	= "http://www.spyany.com/program/article_spw_rm_IMesh.html";
key[i]	= "CLSID\{00000000-6CB0-410C-8C3D-8FA8D2011D0A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iMeshBHO.dll";

i++;
name[i]	= "Transponder parasite variant";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html";
key[i]	= "CLSID\{00000000-C1EC-0345-6EC2-4D0300000000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ZServ.dll";

i++;
name[i]	= "AdBreak";
url[i]	= "http://www.doxdesk.com/parasite/AdBreak.html ";
key[i]	= "CLSID\{00000000-D9E3-4BC6-A0BD-3D0CA4BE5271}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Fhfmm.dll";

i++;
name[i]	= "Transponder variant";
url[i]	= "http://www.webhelper4u.com/transponder/btgrab.html";
key[i]	= "CLSID\{00000000-F09C-02B4-6EC2-AD0300000000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BTGrab.dll";

i++;
name[i]	= "DyFuCa/Internet Optimizer";
url[i]	= "http://www.doxdesk.com/parasite/InternetOptimizer.html";
key[i]	= "CLSID\{00000010-6F7D-442C-93E3-4A4827C2E4C8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "nem219.dll";

i++;
name[i]	= "Adware.Ramdud";
url[i]	= "";
key[i]	= "CLSID\{00000015-A527-34E7-25C2-03A4E313B2E9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winsrvs_1.dll";

i++;
name[i]	= "aBetterinternet/Transponder variant";
url[i]	= "http://doxdesk.com/parasite/Transponder.html ";
key[i]	= "CLSID\{00000026-8735-428D-B81F-DD098223B25F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "speer.dll";

i++;
name[i]	= "aBetterinternet/Transponder";
url[i]	= "http://doxdesk.com/parasite/Transponder.html";
key[i]	= "CLSID\{00000049-8F91-4D9C-9573-F016E7626484}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ceres.dll";

i++;
name[i]	= "FavoriteMan";
url[i]	= "http://www.doxdesk.com/parasite/FavoriteMan.html ";
key[i]	= "CLSID\{000000DA-0786-4633-87C6-1AA7A4429EF1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "emesx.dll";

i++;
name[i]	= "FavoriteMan/FOne";
url[i]	= "http://www.doxdesk.com/parasite/FavoriteMan.html ";
key[i]	= "CLSID\{000000F1-34E3-4633-87C6-1AA7A44296DA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "FOne.dll";

i++;
name[i]	= "SmartBrowser";
url[i]	= "http://www.doxdesk.com/parasite/SmartBrowser.html";
key[i]	= "CLSID\{00000185-B716-11D3-92F3-00D0B709A7D8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BHO.0.1.0";

i++;
name[i]	= "SmartBrowser";
url[i]	= "http://www.doxdesk.com/parasite/SmartBrowser.html";
key[i]	= "CLSID\{00000185-C745-43D2-44F1-01A1C789C738}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BHO.0.1.0";

i++;
name[i]	= "Transponder parasite variant";
url[i]	= "http://webhelper4u.com/transponders/freephone.html";
key[i]	= "CLSID\{00000250-0320-4DD4-BE4F-7566D2314352}\InprocServer32";
item[i]	= NULL;
exp[i]	= "VoiceIP.dll";

i++;
name[i]	= "Transponder";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html ";
key[i]	= "CLSID\{0000026A-8230-4DD4-BE4F-6889D1E74167}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Tps108.dll";

i++;
name[i]	= "Transponder";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html ";
key[i]	= "CLSID\{00000273-8230-4DD4-BE4F-6889D1E74167}\InprocServer32";
item[i]	= NULL;
exp[i]	= "host.dll";

i++;
name[i]	= "IPInsight";
url[i]	= "http://www.doxdesk.com/parasite/IPInsight.html ";
key[i]	= "CLSID\{000004CC-E4FF-4F2C-BC30-DBEF0B983BC9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ipinsigt.dll";

i++;
name[i]	= "VX2 Transponder variant";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html ";
key[i]	= "CLSID\{00000580-C637-11D5-831C-00105AD6ACF0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msview.dll";

i++;
name[i]	= "VX2.aBetterInternet";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html ";
key[i]	= "CLSID\{000006B1-19B5-414A-849F-2A3C64AE6939}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bi.dll";

i++;
name[i]	= "SideSearch";
url[i]	= "http://doxdesk.com/parasite/Sidesearch.html";
key[i]	= "CLSID\{00000762-3965-4A1A-98CE-3D4BF457D4C8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sidesearch.dll";

i++;
name[i]	= "FavoriteMan";
url[i]	= "http://www.doxdesk.com/parasite/FavoriteMan.html";
key[i]	= "CLSID\{00000EF1-0786-4633-87C6-1AA7A44296DA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ATPartners.dll";

i++;
name[i]	= "FavoriteMan";
url[i]	= "http://www.doxdesk.com/parasite/FavoriteMan.html ";
key[i]	= "CLSID\{00000EF1-34E3-4633-87C6-1AA7A44296DA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "F1.dll";

i++;
name[i]	= "TwainTech adware";
url[i]	= "http://www.pchell.com/support/twaintec.shtml";
key[i]	= "CLSID\{000020DD-C72E-4113-AF77-DD56626C6C42}\InprocServer32";
item[i]	= NULL;
exp[i]	= "twaintec.dll";

i++;
name[i]	= "TwainTech adware";
url[i]	= "http://www.pestpatrol.com/PestInfo/t/twain-tech.asp";
key[i]	= "CLSID\{0000607D-D204-42C7-8E46-216055BF9918}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mxTarget.dll";

i++;
name[i]	= "AdsStore adware";
url[i]	= "http://www.pestpatrol.com/PestInfo/a/adsstore.asp";
key[i]	= "CLSID\{00010a21-b924-4cd6-893c-eea1071ae8b3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "PCDBS.DLL";

i++;
name[i]	= "SearchFast parasite";
url[i]	= "http://doxdesk.com/parasite/Searchfst.html";
key[i]	= "CLSID\{000277A3-7D84-406a-9799-D12A81594693}\InprocServer32";
item[i]	= NULL;
exp[i]	= "srchfst.dll";

i++;
name[i]	= "SearchEnhancement hijacker";
url[i]	= "http://www.doxdesk.com/parasite/SCBar.html";
key[i]	= "CLSID\{00041A26-7033-432C-94C7-6371DE343822}\InprocServer32";
item[i]	= NULL;
exp[i]	= "scbar.dll";

i++;
name[i]	= "ShopNav variant";
url[i]	= "http://www.doxdesk.com/parasite/ShopNav.html";
key[i]	= "CLSID\{0007522A-2297-43C1-8EB1-C90B0FF20DA5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "enhtb.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{000E6ED5-E3FC-4c93-99E9-D38D2A9F9B09}\InprocServer32";
item[i]	= NULL;
exp[i]	= "he3e3fc4.dll";

i++;
name[i]	= "NetPal";
url[i]	= "http://www.doxdesk.com/parasite/NetPal.html";
key[i]	= "CLSID\{000E7270-CC7A-0786-8E7A-DA09B51938A6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "n3tpa1.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{00110011-4B0B-44D5-9718-90C88817369B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NavExt.dll";

i++;
name[i]	= "BookedSpace";
url[i]	= "http://www.doxdesk.com/parasite/BookedSpace.html";
key[i]	= "CLSID\{0019C3E2-DD48-4A6D-AB2D-8D32436313D9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "oo4.dll";

i++;
name[i]	= "BookedSpace variant";
url[i]	= "http://www.doxdesk.com/parasite/BookedSpace.html";
key[i]	= "CLSID\{0019C3E2-DD48-4A6D-ABCD-8D32436313D9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bxsx5.dll";

i++;
name[i]	= "BookedSpace variant";
url[i]	= "http://www.doxdesk.com/parasite/BookedSpace.html";
key[i]	= "CLSID\{0019C3E2-DD48-4A6D-ABCD-8D32436323D9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bxxs5.dll";

i++;
name[i]	= "WebSearch";
url[i]	= "http://www.spywareguide.com/product_show.php?id=505";
key[i]	= "CLSID\{001DAE60-95C0-11d3-924E-009027950886}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Spotonbh.dll";

i++;
name[i]	= "AtHoc Toolbar";
url[i]	= "http://www.athoc.com/site/products/portalToolbar.asp";
key[i]	= "CLSID\{001F2470-5DF5-11d3-B991-00A0C9BB0874}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AtHocTBr.DLL";

i++;
name[i]	= "MultiMPP.com adware";
url[i]	= "http://www.multimpp.com/";
key[i]	= "CLSID\{002EB272-2590-4693-B166-FBD5D9B6FEA6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "multimpp.dll";

i++;
name[i]	= "Transponder parasite variant";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html";
key[i]	= "CLSID\{00320615-B6C2-40A6-8F99-F1C52D674FAD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "localNRD.dll";

i++;
name[i]	= "Naupoint toolbar";
url[i]	= "http://doxdesk.com/parasite/Naupoint.html";
key[i]	= "CLSID\{0036F389-FEF8-43AC-9220-16430E0012ED}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iEBINST.dll";

i++;
name[i]	= "Malware taking advantage of the ASN.1 exploit";
url[i]	= "http://www.us-cert.gov/cas/techalerts/TA04-041A.html";
key[i]	= "CLSID\{00673769-777F-4814-BE0F-74CBA1D823B8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iehook.dll";

i++;
name[i]	= "Adware.Slagent";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.simcss.b.html";
key[i]	= "CLSID\{008DB894-99ED-445D-8547-0E7C9808898D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "4b_1,0,1,2_mslagent.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{00A0A40C-F432-4C59-BA11-B25D142C7AB7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "2IN";

i++;
name[i]	= "MyTotalSearch";
url[i]	= "http://www.doxdesk.com/parasite/MySearch.html";
key[i]	= "CLSID\{00BD2861-C654-4694-A44A-98642D73247D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MTSSRCAS.DLL";

i++;
name[i]	= "IncrediFind variant";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{00D6A7E7-4A97-456f-848A-3B75BF7554D7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "PerfectNavBHO.dll";

i++;
name[i]	= "FastFind.org SubSearch";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/subsearch.asp";
key[i]	= "CLSID\{00F16DC8-1B2A-42F4-B18B-E21DA9D2D7FD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "01A00.DLL";

i++;
name[i] = "PolyFilter";
url[i]	= "";
key[i]	= "CLSID\{0140DF95-9128-4053-AE72-F43F0CFCA062}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SiKernel.dll";

i++;
name[i]	= "ExactSearch or MySearch";
url[i]	= "http://www.doxdesk.com/parasite/eXactSearch.html http://doxdesk.com/parasite/MySearch.html";
key[i]	= "CLSID\{014DA6C1-189F-421a-88CD-07CFE51CFF10}\InprocServer32";
item[i]	= NULL;
exp[i]	= "eXacttoolbar.dll";

i++;
name[i]	= "Apropos Adware";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-AproposMedia.aspx";
key[i]	= "CLSID\{016235BE-59D4-4CEB-ADD5-E2378282A1D9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CxtPls.dll";

i++;
name[i]	= "Enhancemysearch.com keyword hijacker";
url[i]	= "";
key[i]	= "CLSID\{017C20C1-F86F-11D8-9B25-000ACD002AE3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Helper100.dll";

i++;
name[i]	= "Incredifind/Keenvalue";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{0199DF25-9820-4bd5-9FEE-5A765AB4371E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IncFindBHO170.dll";

i++;
name[i]	= "PeopleOnPage/AproposMedia";
url[i]	= "http://www.doxdesk.com/parasite/AproposMedia.html ";
key[i]	= "CLSID\{01C5BF6C-E699-4CD7-BEA1-786FA05C83AB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AproposPlugin.dll";

i++;
name[i]	= "IncrediFind/Keenvalue";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{01CD4DDA-166D-4831-A373-ACCC27E1BB9D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IncFindBHO150c.dll";

i++;
name[i]	= "IEPlugin variant";
url[i]	= "http://www.doxdesk.com/parasite/IEPlugin.html";
key[i]	= "CLSID\{01F44A8A-8C97-4325-A378-76E68DC4AB2E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "systb.dll";

i++;
name[i]	= "unknown malware";
url[i]	= "http://www.virit.com/startup/scheda.asp?num=21";
key[i]	= "CLSID\{01FB9C55-FC66-4476-A199-389241193188}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Adware.Slagent";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.simcss.b.html";
key[i]	= "CLSID\{021BB032-80A8-4FB6-B3D5-CF27B1553B95}\InprocServer32";
item[i]	= NULL;
exp[i]	= "4b_1,0,1,0_mslagent.dll";

i++;
name[i]	= "Adlogix InPop";
url[i]	= "";
key[i]	= "CLSID\{024DE5EB-3649-445E-8D57-C09A9A33D479}\InprocServer32";
item[i]	= NULL;
exp[i]	= "phelper.dll";

i++;
name[i]	= "Adware.LizardBar";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.lizardbar.html";
key[i]	= "CLSID\{029BB53A-C312-4b09-9B4F-ED57AF027B28}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winhlp32.dll";

i++;
name[i]	= "VirtuMonde adware variant Vundo";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.vundo.html";
key[i]	= "CLSID\{02F96FB7-8AF6-439B-B7BA-2F952F9E4800}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Trojan.Downloader.Domcom.A";
url[i]	= "";
key[i]	= "CLSID\{031B6D43-CBC4-46A5-8E46-CF8B407C1A33}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ipreg32.dll";

i++;
name[i]	= "Muul.com SiteHistory  hijacker";
url[i]	= "";
key[i]	= "CLSID\{0345B059-8731-42BC-B7B7-5121014B02C6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ChangeURL_30.dll";

i++;
name[i]	= "TOPicks";
url[i]	= "http://www.doxdesk.com/parasite/TOPicks.html ";
key[i]	= "CLSID\{0352960F-47BE-11D5-AB93-00D0B760B4EB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Htcheck2.dll";

i++;
name[i]	= "SmartPops";
url[i]	= "http://www.kephyr.com/spywarescanner/library/smartpops/index.phtml";
key[i]	= "CLSID\{0421701D-CF13-4E70-ADF0-45A953E7CB8B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "RH.dll";

i++;
name[i]	= "IncrediFind variant";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html ";
key[i]	= "CLSID\{0428FFC7-1931-45b7-95CB-3CBB919777E1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "PerfectNavBHO.dll";

i++;
name[i]	= "unidentified hijacker";
url[i]	= "";
key[i]	= "CLSID\{044D9F9F-0EE0-4E9B-B89B-5EBCA0F852CC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "fsearchbar.dll";

i++;
name[i]	= "Actual Names (AdvSearch) Internet Keywords";
url[i]	= "http://www.pestpatrol.com/pestinfo/a/actualnames.asp";
key[i]	= "CLSID\{046D6EA4-15E3-4b27-8010-45BD78A9219E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "inetkw.dll";

i++;
name[i]	= "Excite Search bar";
url[i]	= "http://www.excite.com/ ";
key[i]	= "CLSID\{04719991-296F-4958-AA0F-FA25FFA5008B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "X8bar.dll";

i++;
name[i]	= "Icoo Loader";
url[i]	= "http://www.by-users.co.uk/forums/?board=help&action=display&num=1085918311";
key[i]	= "CLSID\{0519A9C9-064A-4cbc-BC47-D0EACD581477}\InprocServer32";
item[i]	= NULL;
exp[i]	= "icooue.dll";

i++;
name[i]	= "ShopForGood/Marketdart";
url[i]	= "http://www.kephyr.com/spywarescanner/library/shopforgood/index.phtml ";
key[i]	= "CLSID\{05BBB56A-2A69-4A5C-BFDA-43295DD67434}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Winy.dll";

i++;
name[i]	= "StickyPops.com adware";
url[i]	= "";
key[i]	= "CLSID\{06594350-D723-11D8-9669-0800200C9A66}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DNSProxy.dll";

i++;
name[i]	= "Zy web search hijacker";
url[i]	= "";
key[i]	= "CLSID\{06CAD548-14DD-4fa3-9EA9-05F83C18CBD7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MSPXS32.DLL";

i++;
name[i]	= "7FaSSt /7Search";
url[i]	= "http://www.doxdesk.com/parasite/7FaSSt.html ";
key[i]	= "CLSID\{06DFEDAA-6196-11D5-BFC8-00508B4A487D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "7Search.dll";

i++;
name[i]	= "Spyware.BrowserAccel";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/spyware.browseraccel.html";
key[i]	= "CLSID\{074E3AA7-7718-4404-B3F8-FF8FB5414E0E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BrowserAccelerator.dll";

i++;
name[i]	= "Advanced Searchbar";
url[i]	= "http://www.spynet.com/spyware/spyware-Advanced-Searchbar.aspx";
key[i]	= "CLSID\{07531599-F255-4050-B96E-ECE5AA2E63A5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AdvancedBar.dll";

i++;
name[i]	= "Superlogy.com search hijacker";
url[i]	= "";
key[i]	= "CLSID\{08227B4B-54FE-4C4D-809F-BCA46292FC5B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Zedd4.dll";

i++;
name[i]	= "SideStep";
url[i]	= "http://www.doxdesk.com/parasite/SideStep.html ";
key[i]	= "CLSID\{08351226-6472-43BD-8A40-D9221FF1C4CE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SbCIe026.dll";

i++;
name[i]	= "SideStep";
url[i]	= "http://www.doxdesk.com/parasite/SideStep.html";
key[i]	= "CLSID\{08351227-6472-43BD-8A40-D9221FF1C4CE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SbCIe027.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{086AE192-23A6-48D6-96EC-715F53797E85}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DReplace.dll";

i++;
name[i] = "TrafficHog, iLookup variant";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{086CEFD5-A88D-4981-8915-D51F04360ED1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winalot32.dll";

i++;
name[i]	= "BrowserAid/SearchandClick";
url[i]	= "http://www.kephyr.com/spywarescanner/library/browseraid/index.phtml";
key[i]	= "CLSID\{087173EF-9829-4F49-8340-A524177D3F60}\InprocServer32";
item[i]	= NULL;
exp[i]	= "inetp60.dll";

i++;
name[i]	= "Linkz.com AdBlock";
url[i]	= "";
key[i]	= "CLSID\{08C63920-DC18-11D2-9E1E-00A0247061AB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Aphelper.dll";

i++;
name[i]	= "Friends.fr. toolbar";
url[i]	= "http://www.pestpatrol.com/pestinfo/f/friends_fr.asp";
key[i]	= "CLSID\{08DBDE36-DF28-11D5-8CA5-0050DA44A764}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msvri.dll";

i++;
name[i]	= "Trojan.Clicker.Delf.ai";
url[i]	= "";
key[i]	= "CLSID\{08DF42F3-792D-4944-941B-512582B87219}\InprocServer32";
item[i]	= NULL;
exp[i]	= "adobeacr.dll";

i++;
name[i]	= "iWon Search Assistant";
url[i]	= "http://www.doxdesk.com/parasite/Aornum.html";
key[i]	= "CLSID\{08E1C8E1-E565-44fc-A766-C9539BB3ABB7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "I1srchas.dll";

i++;
name[i]	= "Grip Toolbar";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-Grip-Toolbar.aspx";
key[i]	= "CLSID\{08F46458-D00F-4573-8EB3-A9A9E15503F8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NetGuideBHO170.dll";

i++;
name[i]	= "MyTotalSearch";
url[i]	= "http://www.doxdesk.com/parasite/MySearch.html";
key[i]	= "CLSID\{094176F1-BF35-4bcb-B68A-108DFB8C3825}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MTSBAR.DLL";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html ";
key[i]	= "CLSID\{0982868C-47F0-4EFB-A664-C7B0B1015808}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Newads~1.dll";

i++;
name[i]	= "Adware.IAGold";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.iagold.html";
key[i]	= "CLSID\{0A1A2A3A-4A5A-6A7A-8A9A-AABACADAEAFA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "HuntBar/Stoolbar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{0A5CF411-F0BF-4AF8-A2A4-8233F3109BED}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Stoolbar.dll";

i++;
name[i]	= "HuntBar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{0A68C5A2-64AE-4415-88A2-6542304A4745}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msiets.dll";

i++;
name[i]	= "Sexxxpassport.com browser plugin";
url[i]	= "";
key[i]	= "CLSID\{0A7E7249-89E4-4FBF-B256-04DC8F8BAD69}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Spp3.dll";

i++;
name[i] = "Thesearchmall, iLookup variant";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.htm";
key[i]	= "CLSID\{0AEE4D0C-4B38-4196-AE32-70ACE5656647}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winsrm32.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{0B519E07-7824-4adc-8890-93D5EABBF285}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msadocm32.dll";

i++;
name[i]	= "Adlogix.com Zamingo adware";
url[i]	= "http://www.spyany.com/program/article_adw_rm_Zamingo.html";
key[i]	= "CLSID\{0B90AA1B-F649-44C3-9FD3-736C332CBBCF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IEEnhancer.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html ";
key[i]	= "CLSID\{0BA1C6EB-D062-4E37-9DB5-B07743276324}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ms****.dll";

i++;
name[i]	= "SBSoft/EZFinder.com hijacker";
url[i]	= "";
key[i]	= "CLSID\{0CA6C3EA-2054-4011-BC9F-8BBC017A169C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "uns.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{0D7DC475-59EB-4781-985F-A6F5D4E2BC73}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Lie1D6Ff.dll";

i++;
name[i]	= "BrowserAid/FeaturedResults";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html ";
key[i]	= "CLSID\{0DDBB570-0396-44C9-986A-8F6F61A51C2F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msiefr40.dll";

i++;
name[i]	= "Deltabar : Deltaclick";
url[i]	= "http://support.microsoft.com/?kbid=316770 ";
key[i]	= "CLSID\{0FC817C2-3B45-11D4-8340-0050DA825906}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DeltaClick.dll";

i++;
name[i]	= "Whazit";
url[i]	= "http://www.doxdesk.com/parasite/Whazit.html ";
key[i]	= "CLSID\{10955232-B671-11D7-8066-0040F6F477E4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "whattn.dll";

i++;
name[i]	= "CnsMin";
url[i]	= "http://www.doxdesk.com/parasite/CnsMin.html";
key[i]	= "CLSID\{118CE65F-5D86-4AEA-A9BD-94F92B89119F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CnsMinIdn.dll";

i++;
name[i]	= "Sexxxpassport.com browser plugin";
url[i]	= "";
key[i]	= "CLSID\{11904CE8-632A-4856-A7CC-00B33FE71BD8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Spp3.dll";

i++;
name[i]	= "SearchSquire";
url[i]	= "http://www.doxdesk.com/parasite/SearchSquire.html ";
key[i]	= "CLSID\{11990E9F-2A4D-11D6-9507-02608CDD2842}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SearchSquire.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{12D02C08-218F-4A11-BDE1-6611ADB7B81F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sys32_app.dll";

i++;
name[i]	= "Winpage Blocker";
url[i]	= "http://www.pestpatrol.com/pestinfo/w/winpage_blocker.asp";
key[i]	= "CLSID\{12DF6E3E-6272-4AE8-880B-2158D60791C0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WinPage.dll";

i++;
name[i]	= "BrowserAid/Startium variant";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{12EE7A5E-0674-42f9-A76A-000000004D00}\InprocServer32";
item[i]	= NULL;
exp[i]	= "stlb2.dll";

i++;
name[i]	= "ActiveSearch/411Ferret";
url[i]	= "http://www.pestpatrol.com/pestinfo/a/activesearch.asp";
key[i]	= "CLSID\{12F02779-6D88-4958-8AD3-83C12D86ADC7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "toolbar.dll";

i++;
name[i]	= "SuperBar";
url[i]	= "http://www.doxdesk.com/parasite/SuperBar.html";
key[i]	= "CLSID\{136A9D1D-1F4B-43D4-8359-6F2382449255}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Superbar.dll";

i++;
name[i]	= "FavoriteMan";
url[i]	= "http://www.doxdesk.com/parasite/FavoriteMan.html";
key[i]	= "CLSID\{139D88E5-C372-469D-B4C5-1FE00852AB9B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ofrg.dll";

i++;
name[i]	= "p0rn related";
url[i]	= "";
key[i]	= "CLSID\{13F90341-AD79-4A9F-9B57-0234675670D6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ipsysdrv32.dll";

i++;
name[i]	= "StickyPops.com adware";
url[i]	= "";
key[i]	= "CLSID\{1433F750-E53F-11D8-9669-0800200C9A66}\InprocServer32";
item[i]	= NULL;
exp[i]	= "STRAd32.dll";

i++;
name[i]	= "ShopNavSearch/Srng";
url[i]	= "http://www.doxdesk.com/parasite/Srng.html ";
key[i]	= "CLSID\{14B3D246-6274-40B5-8D50-6C2ADE2AB29B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Snhelper.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{150FA160-130D-451F-B863-B655061432BA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mgs_32.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{166348F1-2C41-4C9F-86BB-EB2B8ADE030C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msvrfy";

i++;
name[i]	= "Comet Cursor";
url[i]	= "http://www.doxdesk.com/parasite/CometCursor.html";
key[i]	= "CLSID\{1678F7E1-C422-11D0-AD7D-00400515CAAA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "comet.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{17DA0C9E-4A27-4ac5-BB75-5D24B8CDB972}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Excel10.dll";

i++;
name[i]	= "Spyware.DigitalNames variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/spyware.digitalnames.html";
key[i]	= "CLSID\{183D5161-0C62-4295-896C-44E7442CD6F2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DigitalNamesPlugIn150.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{18722863-6D1D-4300-BF29-406948EDA7CB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "I-Lookup";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{18B79968-1A76-4953-9EBB-B651407F8998}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winenc32.dll";

i++;
name[i]	= "i-lookup/Sbus";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{19A447BA-9C2E-4864-93F5-A0645229771E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Sbus.dll";

i++;
name[i]	= "SearchEx";
url[i]	= "http://www.doxdesk.com/parasite/Searchex.html";
key[i]	= "CLSID\{1A98BCA2-0BD1-47DE-9710-C7665F7F1FCB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iebrw.dll";

i++;
name[i]	= "CnsMin";
url[i]	= "http://www.aluriasoftware.com/spyware-removal/details/CnsMin/";
key[i]	= "CLSID\{1B0E7716-898E-48cc-9690-4E338E8DE1D3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Assist.dll";

i++;
name[i]	= "Clickspring/PurityScan";
url[i]	= "http://doxdesk.com/parasite/PurityScan.html";
key[i]	= "CLSID\{1B7D753B-1981-4bd2-91F3-6D055EE113A0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NDrv.dll";

i++;
name[i]	= "Browserplugin.com malware";
url[i]	= "";
key[i]	= "CLSID\{1BDD55B8-3985-4E59-B906-5E0AD56D6710}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WH";

i++;
name[i]	= "Adware.IEPageHelper";
url[i]	= "http://www.pestpatrol.com/pestinfo/a/adware_iepagehelper.asp";
key[i]	= "CLSID\{1C4DA27D-4D52-4465-A089-98E01BB725CA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "inetdctr.dll";

i++;
name[i]	= "iSearch toolbar";
url[i]	= "http://www.kephyr.com/spywarescanner/library/isearch/index.phtml";
key[i]	= "CLSID\{1C78AB3F-A857-482e-80C0-3A1E5238A565}\InprocServer32";
item[i]	= NULL;
exp[i]	= "toolbar.dll";

i++;
name[i] = "SpiderSearch, iLookup variant";
url[i]	= "";
key[i]	= "CLSID\{1D022C27-3771-4D1D-B1B7-1953E271C6CA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winsps32.dll";

i++;
name[i]	= "BlazeFind/SearchRelevancy hijacker";
url[i]	= "";
key[i]	= "CLSID\{1D7E3B41-23CE-469B-BE1B-A64B877923E1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SearchRelevancy.dll";

i++;
name[i]	= "SubSearch v22";
url[i]	= "http://www.doxdesk.com/parasite/SubSearch.html";
key[i]	= "CLSID\{1D870C86-AA3C-4451-81E4-71D480A1A652}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SbSrch_V22.dll";

i++;
name[i]	= "NJStar Asian Explorer";
url[i]	= "http://www.njstar.com/asianexplorer/";
key[i]	= "CLSID\{1E1B2879-30C7-11D4-8DDF-525400E483E3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ETop100.dll";

i++;
name[i]	= "Backdoor.Lixy.B";
url[i]	= "http://www.symantec.com/avcenter/venc/data/backdoor.lixy.b.html";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-000000000003}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SSocks5.dll";

i++;
name[i]	= "Backdoor.Lixy.B";
url[i]	= "http://www.symantec.com/avcenter/venc/data/backdoor.lixy.b.html";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-000000000004}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ssocks32.dll";

i++;
name[i]	= "Clitor";
url[i]	= "http://www.pestpatrol.com/pestinfo/c/clitor.asp";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-123457123457}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Explorer.dll";

i++;
name[i]	= "unidentified adware";
url[i]	= "";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-D7ACAC31337F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Mslink32.dll";

i++;
name[i]	= "BackDoor Lixy";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.lixy.html";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-D7ACAC95951A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Lid.dll";

i++;
name[i]	= "Commonname toolbar";
url[i]	= "http://www.doxdesk.com/parasite/CommonName.html";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CnbarIE.dll";

i++;
name[i]	= "CooolWebSearch parasite variant";
url[i]	= "http://www.spywareinfo.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DNSErr.dll";

i++;
name[i]	= "GoGoTools";
url[i]	= "http://doxdesk.com/parasite/GogoTools.html parasite";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "HTMLEdit.dll";

i++;
name[i]	= "p0rn related";
url[i]	= "";
key[i]	= "CLSID\{1E1B2879-88FF-11D2-8D96-D7ACAC97972F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msudp.dll";

i++;
name[i]	= "Personal Antispy keylogger";
url[i]	= "http://www.botspot.com/Intelligent_Agent/2235.html";
key[i]	= "CLSID\{1E1B2879-88FF-11D3-8D96-D7ACAC95951A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Funnywb.dll";

i++;
name[i]	= "QuickFlicks Streaming Player";
url[i]	= "http://www.pestpatrol.com/PestInfo/db/q/quickflicks_streaming_player.asp";
key[i]	= "CLSID\{1E6F1D6A-1F20-11D4-8859-00A0CCE26836}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SVAplayer.dll";

i++;
name[i]	= "ToolbarCC";
url[i]	= "http://www.doxdesk.com/parasite/ToolbarCC.html";
key[i]	= "CLSID\{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFA2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "ToolbarCC/Rnd";
url[i]	= "http://www.doxdesk.com/parasite/ToolbarCC.html";
key[i]	= "CLSID\{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFA7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "win";

i++;
name[i]	= "ToolbarCC/Rnd";
url[i]	= "http://www.doxdesk.com/parasite/ToolbarCC.html";
key[i]	= "CLSID\{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFA8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "win";

i++;
name[i]	= "ToolbarCC/Rnd";
url[i]	= "http://www.doxdesk.com/parasite/ToolbarCC.html ";
key[i]	= "CLSID\{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFAF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFB1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MS";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFB2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MS";

i++;
name[i]	= "i-lookup/Abeb";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html ";
key[i]	= "CLSID\{2038A287-4221-4F76-A7C0-ADDD77AFABB3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "abeb.dll";

i++;
name[i]	= "Myaopop Adware";
url[i]	= "";
key[i]	= "CLSID\{204E9F8F-38CA-4E11-BA91-06B685285CC0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "xpllog.dll";

i++;
name[i]	= "HotBar";
url[i]	= "http://www.doxdesk.com/parasite/HotBar.html";
key[i]	= "CLSID\{204F937E-519E-4597-96FA-8F1F59F3CB6D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ctor.dll";

i++;
name[i]	= "Give4Free";
url[i]	= "";
key[i]	= "CLSID\{208E7E77-507A-4649-B0C9-D39E9049C7A2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ibho.dll";

i++;
name[i]	= "CustomToolbar";
url[i]	= "http://www.doxdesk.com/parasite/CustomToolbar.html ";
key[i]	= "CLSID\{21301D69-B8F1-46AA-B0B5-09EE2285914C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CustomToolbar.dll";

i++;
name[i]	= "SearchEnhancement hijacker";
url[i]	= "http://groups.google.com/groups?q=searchenhancement&hl=en&lr=&ie=UTF-8&oe=UTF-8&selm=5fa201c33b6c%24abac7a20%243101280a%40phx.gbl&rnum=1 ";
key[i]	= "CLSID\{22941A26-7033-432C-94C7-6371DE343822}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Scbar.dll";

i++;
name[i] = "hijacker,  as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{22B9A67D-E689-44B6-B775-0E8FE84B4F9B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{2316230A-C89C-4BCC-95C2-66659AC7A775}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Expext/MetaDirect hijacker";
url[i]	= "http://www.securemost.com/articles/trou_3_remove_expext.htm";
key[i]	= "CLSID\{23BC1CCF-4BE7-497F-B154-6ADA68425FBB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "expext.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{25F7FA20-3FC3-11D7-B487-00D05990014C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ms";

i++;
name[i]	= "Xupiter";
url[i]	= "http://www.doxdesk.com/parasite/Xupiter.html";
key[i]	= "CLSID\{2662BDD7-05D6-408F-B241-FF98FACE6054}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Xtupdate.dll";

i++;
name[i]	= "Whazit";
url[i]	= "http://www.doxdesk.com/parasite/Whazit.html";
key[i]	= "CLSID\{267D5BD3-0DC2-4724-A196-7F4794FBB9EB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "outones.dll";

i++;
name[i]	= "eUniverse/Keenvalue variant";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{269B6797-664E-48AA-B283-B012BDF6E525}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BHO.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{2737A6C0-7E24-11D7-B299-00E0297E0844}\InprocServer32";
item[i]	= NULL;
exp[i]	= "";

i++;
name[i]	= "WhistleSoftware";
url[i]	= "http://www.uslocalweather.com/privacy.asp";
key[i]	= "CLSID\{27557cf1-a237-496d-8c8f-08f3844c6a8b}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WhistleHelper.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{275636E4-A535-4668-9FF1-86DC0C62D446}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msopt.dll";

i++;
name[i]	= "MyPageFinder";
url[i]	= "http://www.doxdesk.com/parasite/MyPageFinder.html";
key[i]	= "CLSID\{27A5FF76-9919-492C-98E3-EDA3502FC829}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ml_32.dll";

i++;
name[i]	= "SearchMiracle.EliteBar";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-SearchMiracle.EliteBar.aspx";
key[i]	= "CLSID\{28CAEFF3-0F18-4036-B504-51D73BD81ABC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "EliteToolBar version 53.dll";

i++;
name[i]	= "EliteBar/SearchMiracle adware";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-SearchMiracle.EliteBar.aspx";
key[i]	= "CLSID\{28CAEFF3-0F18-4036-B504-51D73BD81C3A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Elitebar.dll";

i++;
name[i]	= "Searchportal.info - CoolWebSearch parasite variant";
url[i]	= "http://www.spywareinfo.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{28F65FCB-D130-11D8-BA48-8BE0C49AF370}\InprocServer32";
item[i]	= NULL;
exp[i]	= "popup_bl.dll";

i++;
name[i]	= "unidentified hijacker";
url[i]	= "";
key[i]	= "CLSID\{29A38549-AF6F-11D4-89D6-BC1DFD912B00}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bho1.dll";

i++;
name[i]	= "Commander toolbar";
url[i]	= "http://www.pestpatrol.com/pestinfo/c/commander_toolbar.asp";
key[i]	= "CLSID\{29F7B7FA-ADC8-48ea-9E1C-EA87A05AE642}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sbb.dll";

i++;
name[i]	= "FastFind.org SubSearch";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/subsearch.asp";
key[i]	= "CLSID\{2A57772A-D963-4533-A999-A4D66B7EF424}\InprocServer32";
item[i]	= NULL;
exp[i]	= "00S00.dll";

i++;
name[i]	= "Make-deal.com malware";
url[i]	= "";
key[i]	= "CLSID\{2A7B720A-7A28-4e99-80A0-2DF985EC93D0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Font.dll";

i++;
name[i]	= "SmartShopper";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-Hotbar.ShoppingReports.aspx";
key[i]	= "CLSID\{2A8A997F-BB9F-48F6-AA2B-2762D50F9289}\InprocServer32";
item[i]	= NULL;
exp[i]	= "smrtshpr.dll";

i++;
name[i]	= "LookThru Cool Search Bar";
url[i]	= "";
key[i]	= "CLSID\{2AF8CED6-5BD8-4310-A90C-9664EFB16B10}\InprocServer32";
item[i]	= NULL;
exp[i]	= "coolbar.dll";

i++;
name[i]	= "BookedSpace/Remanent";
url[i]	= "http://www.doxdesk.com/parasite/BookedSpace.html";
key[i]	= "CLSID\{2B3452C5-1B9A-440F-A203-F6ED0F64C895}\InprocServer32";
item[i]	= NULL;
exp[i]	= "rem00001.dll";

i++;
name[i]	= "Dynamic Desktop Media adware";
url[i]	= "http://www.spyany.com/program/article_spw_rm_Dynamic_Desktop_Media.html";
key[i]	= "CLSID\{2BC43670-C0BD-4794-BB11-F60F3E001DC5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ddmp.dll";

i++;
name[i]	= "IESearch Toolbar";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-IESearchToolbar.aspx";
key[i]	= "CLSID\{2c5175a2-adf3-4f57-ab70- ba90fd60a383}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IESEARCHTOOLBAR.DLL";

i++;
name[i]	= "IESearch toolbar hijacker";
url[i]	= "";
key[i]	= "CLSID\{2C5175A2-ADF3-4F57-AB70-BA90FD60A383}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IESearchToolbar.dll";

i++;
name[i]	= "BrowserAid/Startium";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{2CF0B992-5EEB-4143-99C0-5297EF71F443}\InprocServer32";
item[i]	= NULL;
exp[i]	= "stlbdist.dll";

i++;
name[i]	= "BrowserAid/Startium";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{2CF0B992-5EEB-4143-99C0-5297EF71F444}\InprocServer32";
item[i]	= NULL;
exp[i]	= "stlbdist.dll";

i++;
name[i]	= "BrowserAid/Startium";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{2CF0B992-5EEB-4143-99C0-5297EF71F44A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "stlbad123.dll";

i++;
name[i]	= "BrowserAid/Startium";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{2CF0B992-5EEB-4143-99C2-5297EF71F44A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "stlbad123.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{2D38A51A-23C9-48a1-A33C-48675AA2B494}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winres.dll";

i++;
name[i]	= "i-lookup/Drbr";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html ";
key[i]	= "CLSID\{2D556983-83D7-4630-9AA5-27C74CA27B79}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Drbr.dll";

i++;
name[i]	= "AdBlaster Adware";
url[i]	= "http://www.spyany.com/program/article_adw_rm_AdBlaster.html";
key[i]	= "CLSID\{2D7CB618-CC1C-4126-A7E3-F5B12D3BCF71}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ngpw34.dll";

i++;
name[i]	= "GoGoData toolbar";
url[i]	= "http://gogodata.com/toolbar/index.htm";
key[i]	= "CLSID\{2D877C0B-3F44-42CD-A283-57AAA9186CB9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "GoGoDataBar.dll";

i++;
name[i]	= "VX2.aBetterInternet variant";
url[i]	= "";
key[i]	= "CLSID\{2DC9D850-144D-11E1-B3C9-10805E499D95}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mplay32.dll";

i++;
name[i]	= "InetSpeak";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{2E12B523-3D4C-4FAC-9B04-0376A8F5E879}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WindowsIE.dll";

i++;
name[i]	= "FastFind adware variant";
url[i]	= "http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_STARTPAG.KF&VSect=T";
key[i]	= "CLSID\{2E65A557-173C-4DE9-860B-28FC5CACA542}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Setup.dll";

i++;
name[i]	= "P0rn related";
url[i]	= "";
key[i]	= "CLSID\{2E77E33F-671E-4334-ABAA-0C2E2BE654F1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mdv_32.dll";

i++;
name[i]	= "SubmitHook";
url[i]	= "http://www.lurhq.com/submithook.html";
key[i]	= "CLSID\{2E9CAFF6-30C7-4208-8807-E79D4EC6F806}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Submithook.dll";

i++;
name[i]	= "ezSearching";
url[i]	= "http://doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{2F24B54D-3A27-11D8-8169-00C02623048A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Testadit3.dll";

i++;
name[i]	= "Porn Hijacker";
url[i]	= "";
key[i]	= "CLSID\{2FF5573C-0EB5-43db-A1B2-C4326813468E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iehr.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{30192F8D-0958-44E6-B54D-331FD39AC959}\InprocServer32";
item[i]	= NULL;
exp[i]	= "toolband.dll";

i++;
name[i]	= "SBSoft IWantSearch hijacker";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.iwantsearch.html";
key[i]	= "CLSID\{30192F8D-0958-44E6-B54D-331FD39AC959}\InprocServer32";
item[i]	= NULL;
exp[i]	= "rundlg32.dll";

i++;
name[i] = "SBSoft Web-Search hijacker variant, a member of the CoolWebSearch parasite family";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.iwantsearch.html";
key[i]	= "CLSID\{30192F8D-0958-44E6-B54D-331FD39AC959}\InprocServer32";
item[i]	= NULL;
exp[i]	= "webdlg32.dll";

i++;
name[i]	= "EZtracks/Pickoftheweb toolbar";
url[i]	= "";
key[i]	= "CLSID\{3023AF97-870E-476A-B30E-3923DF2B84BD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "eztracks_ieplug.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{30279F2D-1A38-4785-97D4-5C3508BDB289}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Adware.OpenSite";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.opensite.html";
key[i]	= "CLSID\{30A56549-9D5B-4D34-AFA7-440A7F0538A9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Opnste.dll";

i++;
name[i]	= "ProBot Activity Monitor";
url[i]	= "http://www.pestpatrol.com/PestInfo/P/ProBot_Activity_Monitor.asp";
key[i]	= "CLSID\{312FA154-E1B7-4336-9833-EE6B38D58B56}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pbcommon.dll";

i++;
name[i]	= "SubSearch v22";
url[i]	= "http://www.doxdesk.com/parasite/SubSearch.html";
key[i]	= "CLSID\{31995C64-CB4D-483E-82C2-CCFFE2F66CAB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msvcn.dll";

i++;
name[i]	= "ezSearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{34D516EA-40E3-4E3B-8BA8-505112738ED5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ctavp3.dll";

i++;
name[i]	= "i-Lookup/Chgrgs";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{35CC7369-C6EB-4A64-AB05-44CF0B5087A0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Chgrgs.dll";

i++;
name[i]	= "E2Give";
url[i]	= "http://www.doxdesk.com/parasite/E2Give.html";
key[i]	= "CLSID\{3643ABC2-21BF-46B9-B230-F247DB0C6FD6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IeBHOs.dll";

i++;
name[i]	= "Burnaby Module >e-card_viewer";
url[i]	= "http://www.symantec.com/avcenter/venc/data/ortyc.trojan.html";
key[i]	= "CLSID\{3750BFA3-1392-4AF3-AF86-9D2D4776E5A4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "potd.dll";

i++;
name[i]	= "Oasisnet.com Hijacker/web downloader";
url[i]	= "";
key[i]	= "CLSID\{37A5FF76-9919-492C-98E3-EDA3502FC829}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Oasis.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{388D7EBB-CBB9-4126-8DB2-86DC6863A206}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr11.dll";

i++;
name[i]	= "BookedSpace";
url[i]	= "http://www.doxdesk.com/parasite/BookedSpace.html";
key[i]	= "CLSID\{392BE62B-E7DE-430A-8859-0AFE677DE6E1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bs2.dll";

i++;
name[i] = "Hijacker, as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{397D7D63-816E-4ECF-8761-775C932C5CF1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iDonate.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{39AF31DD-EAFC-45EA-A56C-385B52E25CC0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr22.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{3A279869-C6B6-4410-A041-0435DE6AD916}\InprocServer32";
item[i]	= NULL;
exp[i]	= "M030106SHOP.DLL";

i++;
name[i]	= "Wishbone Toolbar";
url[i]	= "http://www.wishbonemedia.com/products.html";
key[i]	= "CLSID\{3AA90BC2-58C0-4F4D-A87C-2C6F3D3CD5FE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Minst.dll";

i++;
name[i]	= "LZIO.com adware";
url[i]	= "http://www.spywareguide.com/product_show.php?id=853";
key[i]	= "CLSID\{3BC2C2D1-758E-4912-BED2-AE50DE69E8AF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iedcb1f5.dll";

i++;
name[i]	= "Alexa";
url[i]	= "http://www.safersite.com/PestInfo/a/Alexa_Toolbar.asp";
key[i]	= "CLSID\{3DF73DF8-41E2-4fc2-8CBF-4B9407433755}\InprocServer32";
item[i]	= NULL;
exp[i]	= "lxTB.dll";

i++;
name[i]	= "porn hijacker";
url[i]	= "";
key[i]	= "CLSID\{3E307D7F-5F68-4ddb-9294-EE230950F60C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winacl.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{3EC8E271-FAB9-418a-8A8E-65AEB4029E64}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Traffix Inc/iMatchup";
url[i]	= "http://www.webhelper4u.com/transponders/potwbar.html";
key[i]	= "CLSID\{3F68A524-6E47-44E6-9FE7-795EABFA3B36}\InprocServer32";
item[i]	= NULL;
exp[i]	= "traffix1.1.0.25.dll";

i++;
name[i]	= "Not yet identified malware";
url[i]	= "";
key[i]	= "CLSID\{40205287-E793-41AC-B95C-D8D064BA33CA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mscfg.dll";

i++;
name[i]	= "WurldMedia/bpboh";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{40AC4D2D-491D-11D4-AAF2-0008C75DCD2B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bpboh.dll";

i++;
name[i]	= "Popmonster adware";
url[i]	= "http://www.pestpatrol.com/PestInfo/p/popmonster.asp";
key[i]	= "CLSID\{4209B4C1-1295-4908-9312-A53C036EB3CD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BHO.dll";

i++;
name[i]	= "PBar";
url[i]	= "http://www.pbar.net/?id=BAFDJFFBBEdDBEZKVCSKL";
key[i]	= "CLSID\{42132494-F48F-4187-ABC8-0F343AD2E465}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Pbshmd.dll";

i++;
name[i]	= "Dyfuca/Internet Optimizer";
url[i]	= "http://www.doxdesk.com/parasite/InternetOptimizer";
key[i]	= "CLSID\{432D8C41-8586-11D8-997D-00C026232EB9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bvm202.dll";

i++;
name[i]	= "LoveTester foistware";
url[i]	= "http://spamwatch.codefish.net.au/modules.php?op=modload&name=News&file=index&catid=&topic=24";
key[i]	= "CLSID\{43FA5935-E36E-4937-8127-A90191B2EC68}\InprocServer32";
item[i]	= NULL;
exp[i]	= "domain11.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{441354C5-911B-409B-9A66-A11D6D4E1A22}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sdmtb.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{446CF8A5-617E-4D91-95AE-AE78CE0D06AF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{447160CD-ECF5-4EA2-8A8A-1F70CA363F85}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bundle";

i++;
name[i]	= "Msinfosys/AutoSearch hijacker";
url[i]	= "http://www.doxdesk.com/parasite/AutoSearch.html";
key[i]	= "CLSID\{44A23DAB-8D31-43AE-9F68-5AC24CF7CE8C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msinfosys.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{44E5B409-35A2-4E8D-BF94-344222323A53}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Naupoint toolbar";
url[i]	= "http://doxdesk.com/parasite/Naupoint.html";
key[i]	= "CLSID\{44FD0AF8-9D30-4E96-8ECE-306446B5E0D3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iEBINST2.dll";

i++;
name[i]	= "Icoo Loader";
url[i]	= "http://www.by-users.co.uk/forums/?board=help&action=display&num=1085918311";
key[i]	= "CLSID\{465A59EC-20E5-4fca-A38A-E5EC3C480218}\InprocServer32";
item[i]	= NULL;
exp[i]	= "icoou.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{467FAEB2-5F5B-4c81-BAE0-2A4752CA7F4E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "W32.Aspam.Trojan.B";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/w32.aspam.trojan.b.html";
key[i]	= "CLSID\{499DB658-1909-420B-931A-4A8CAEFD232F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Drvman32.dll";

i++;
name[i]	= "NewDotNet";
url[i]	= "http://www.doxdesk.com/parasite/NewDotNet.html";
key[i]	= "CLSID\{4A2AACF3-ADF6-11D5-98A9-00E018981B9E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "newdotnet";

i++;
name[i]	= "ezSearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{4B021269-DD24-48B2-96B4-DA121E9C0502}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ctpp";

i++;
name[i]	= "StartNow/HyperBar";
url[i]	= "http://www.pestpatrol.com/pestinfo/s/startnow_hyperbar.asp";
key[i]	= "CLSID\{4B2F5308-2CB0-40E2-8030-59936ED5D22C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Hyperbar.dll";

i++;
name[i]	= "Adware.Sa";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.sa.html";
key[i]	= "CLSID\{4BCF322B-9621-4e90-9678-F1424EB7584E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Udpmod.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{4C1B116F-2860-46db-8E6C-B4BFC4DFD683}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ietlbass32.dll";

i++;
name[i]	= "SubSearch";
url[i]	= "http://www.doxdesk.com/parasite/SubSearch.html";
key[i]	= "CLSID\{4C4871FD-30F6-4430-8834-BC75D58F1529}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Sbsrch_v2.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{4CEBBC6B-5CEE-4644-80CF-38980BAE93F6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iexplorr23.dll";

i++;
name[i] = "Begin2Search bar, iLookup variant";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{4D568F0F-8AC9-40AB-88B7-415134C78777}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";
#adpop.dll, winb2s3*.dll

i++;
name[i]	= "Trojan-Clicker.Win32.Delf.bc";
url[i]	= "";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-85AC-FD60BB9AAE32}\InprocServer32";
item[i]	= NULL;
exp[i]	= "seotoolbar.dll";

i++;
name[i]	= "2020Search";
url[i]	= "http://www.kephyr.com/spywarescanner/library/2020search/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-92C6-CE7EB590A94D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "2020Search2.dll";

i++;
name[i]	= "Naupoint toolbar";
url[i]	= "http://doxdesk.com/parasite/Naupoint.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-95BE-B378BA9CB52D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Naupointbar.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-96F7-EB6DB99AA92E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "gssomatic.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-98F7-EB6DB99AA93B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ifsomatic.dll";

i++;
name[i]	= "Push toolbar";
url[i]	= "";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-A0E8-F76FA694BF2E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "searchv2.dll";

i++;
name[i] = "Hijacker,  as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-A1F6-FC7EB590A97D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "search3.dll";

i++;
name[i]	= "KeenValue/PowerSearch";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-A3EE-FB7FA682AA7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pwrsdp1.dll";

i++;
name[i]	= "KeenValue/PowerSearch";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-A3FA-F161A787AD2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pwrsmnd1.dll";

i++;
name[i]	= "Grip Toolbar";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-Grip-Toolbar.aspx";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-A4E4-FC7CBD87BD7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "gripcz6.dll";

i++;
name[i]	= "PowerSearch toolbar";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-A58D-8F6FA787AD2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "PWRSC037.DLL";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.wzhelper/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FB-EF60B19DA02A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Wzhelper.dll";

i++;
name[i]	= "SRNG/ShopNav";
url[i]	= "http://www.doxdesk.com/parasite/Srng.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FB-EF60B19DB42E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SNHelper.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FB-EF60B19DBC34}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ifhelper.dll";

i++;
name[i]	= "KeenValue/PowerSearch";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FC-F378A787AD2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Toolbarpwrstlbr.dll";

i++;
name[i]	= "eUniverse SirSearch";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FC-F76FA694BF2E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Searchbr.dll";

i++;
name[i]	= "MegaSearch";
url[i]	= "http://doxdesk.com/parasite/MegaSearch.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FF-FA7FB592BF30}\InprocServer32";
item[i]	= NULL;
exp[i]	= "megasear.dll";

i++;
name[i]	= "Gamebar";
url[i]	= "http://member.game.net/Membership/Privacy.asp";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FF-FD69B994BD7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "gamebar.dll";

i++;
name[i]	= "PickOfTheWeb toolbar";
url[i]	= "http://www.webhelper4u.com/transponders/potwbar.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FF-FD7BA09AAA7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "potwbar.dll";

i++;
name[i]	= "eUniverse SearchNugget Toolbar";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C0FF-FD7FF4D5FA7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sbar.dll";

i++;
name[i]	= "KeenValue/PowerSearch";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-C8FB-FC6DA787AD2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pwrsacez.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-D1F7-EB6DB99AA97D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "somatic.dll";

i++;
name[i]	= "Voonda Toolbar";
url[i]	= "http://www.pestpatrol.com/pestinfo/v/voonda_toolbar.asp";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-D4FF-EB2CF4D5FA7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "taf.dll";

i++;
name[i]	= "KeenValue/PowerSearch";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-D4FF-ED78A787AD2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pwrstraf.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.webalize/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-D7E4-F660B597BF2A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Webalize.dll";

i++;
name[i]	= "BrowserVillage Toolbar";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-BrowserVillage-Toolbar.aspx";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-D7F9-FE60B89CAC3F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bvillage.dll";

i++;
name[i]	= "SearchCentrix variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.mygeek/index.phtml ";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-D9FB-FA6BAD98FA7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MyGeek.dll - MyGeek/Search-o-Matic2000";

i++;
name[i]	= "InstaFinder hijacker";
url[i]	= "";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-DCF7-F96DA086B434}\InprocServer32";
item[i]	= NULL;
exp[i]	= "instafin.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.mygeek/index.phtml";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-DFF7-EC6BF4D5FA7D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "gsim.dll";

i++;
name[i]	= "KeenValue/Powersearch variant";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-DFF7-EC7DA787AD2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Pwrsqsim.dll";

i++;
name[i]	= "404Search";
url[i]	= "http://doxdesk.com/parasite/404Search.html";
key[i]	= "CLSID\{4E7BD74F-2B8D-469E-EEFD-ED6DB186CE4D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "404Search.dll";

i++;
name[i]	= "IncrediFind/Keenvalue";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{4FC95EDD-4796-4966-9049-29649C80111D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "incfindbho.dll";

i++;
name[i]	= "SeekSeek";
url[i]	= "http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=ADW_SCANPORTAL.A&VSect=T";
key[i]	= "CLSID\{5074851C-F67A-488E-A9C9-C244573F4068}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iesearch.dll";

i++;
name[i]	= "AdBars";
url[i]	= "http://www.pestpatrol.com/pestinfo/a/adbars.asp";
key[i]	= "CLSID\{51641EF3-8A7A-4D84-8659-B0911E947CC8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DownloadHtml.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html ";
key[i]	= "CLSID\{525BBD23-1863-46C6-86D6-5F9A3715D44E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mbho.dll";

i++;
name[i]	= "NetNucleus/Mirar webband";
url[i]	= "http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb40/index.phtml";
key[i]	= "CLSID\{528DA727-EC08-461E-9564-DF5C971E8574}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WinNB40.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{52DC9EC1-35A9-4914-98D9-D568A9854DA2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "DigitalNames spyware related";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/spyware.digitalnames.html";
key[i]	= "CLSID\{531553EB-B210-4116-BC2C-C09608F4193E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SetGlbHO.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{5321E378-FFAD-4999-8C62-03CA8155F0B3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "1.00.07.dll";

i++;
name[i]	= "404Search";
url[i]	= "http://doxdesk.com/parasite/404Search.html";
key[i]	= "CLSID\{53C330D6-A4AB-419B-B45D-FD4411C1FEF4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "404Search.dll";

i++;
name[i]	= "WinAd";
url[i]	= "http://www.kephyr.com/spywarescanner/library/winad/index.phtml";
key[i]	= "CLSID\{53D3C442-8FEE-4784-9A21-6297D39613F0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Winad2.dll";

i++;
name[i]	= "HighTraffic";
url[i]	= "http://www.doxdesk.com/parasite/HighTraffic.html";
key[i]	= "CLSID\{53E10C2C-43B2-4657-BA29-AAE179E7D35C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BHO2.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{5483427F-93B8-1470-5A89-E6B56484CDB2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{54ED9B49-81D1-4866-95A6-30F01DE0047E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr29.dll";

i++;
name[i]	= "from imu.com.cn";
url[i]	= "";
key[i]	= "CLSID\{54F8C0E2-34F9-474F-B47F-2CFCFE2300A2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IMULiver.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{55E301E5-BA44-4095-BB0B-14E0123CCF71}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{564FFB73-9EEF-4969-92FA-5FC4A92E2C2A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sfg_";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{5742F79A-1D91-42c4-990C-B46CF55A6478}\InprocServer32";
item[i]	= NULL;
exp[i]	= "setfgi.dll";

i++;
name[i]	= "Adware.Margoc variant";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.margoc.html";
key[i]	= "CLSID\{57CD6D2E-0291-488F-B846-AF101B367DD5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Ezula TopText";
url[i]	= "http://www.cexx.org/toptext.htm";
key[i]	= "CLSID\{58359010-BF36-11D3-99A2-0050DA2EE1BE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "eabh.dll";

i++;
name[i]	= "Gratisware";
url[i]	= "http://www.doxdesk.com/parasite/Gratisware.html";
key[i]	= "CLSID\{5843A29E-1246-11D4-BA8C-0050DA707ACD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "crs32.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{587DBF2D-9145-4c9e-92C2-1F953DA73773}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iefeatsl.dll";

i++;
name[i]	= "TotalVelocity zSearch";
url[i]	= "http://www.pestpatrol.com/pestinfo/t/totalvelocity_zsearch.asp";
key[i]	= "CLSID\{5886A6DC-AAF4-45E9-979A-8E5E6DEE30E7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "zSearch.dll";

i++;
name[i]	= "JimmySurf";
url[i]	= "http://www.pestpatrol.com/PestInfo/j/jimmysurf.asp";
key[i]	= "CLSID\{5998B08E-CFAC-11D5-822A-0050048E6E38}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SurfPlugin.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{5A3A5040-4210-11D7-BD2E-00080E34122F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "M030206POHS.DLL";

i++;
name[i]	= "iSearch Desktop Search toolbar";
url[i]	= "";
key[i]	= "CLSID\{5B4AB8E2-6DC5-477A-B637-BF3C1A2E5993}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sysupd.dll";

i++;
name[i]	= "eSearch browser Hijacker";
url[i]	= "http://www.vsantivirus.com/troj-startpage-lg.htm";
key[i]	= "CLSID\{5C472352-90D0-4214-BF20-8E4A2B82F980}\InprocServer32";
item[i]	= NULL;
exp[i]	= "win32app.dll";

i++;
name[i]	= "IncrediFind/Keenvalue";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{5D60FF48-95BE-4956-B4C6-6BB168A70310}\InprocServer32";
item[i]	= NULL;
exp[i]	= "incfindbho.dll";

i++;
name[i]	= "180solutions";
url[i]	= "http://www.surfassistant.com/eula.html";
key[i]	= "CLSID\{5DAFD089-24B1-4c5e-BD42-8CA72550717B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "saiemod.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{5ED50735-B0D9-47C6-9774-02DD8E6FE053}\InprocServer32";
item[i]	= NULL;
exp[i]	= "disable.dll";

i++;
name[i]	= "BrowserAid CashToolbar/QuickLaunch toolbar";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{5F5564AC-DE7A-4DCD-9296-32E71A35DCB6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Browseraidtoolbar.dll";

i++;
name[i]	= "BrowserPal toolbar";
url[i]	= "http://www.doxdesk.com/parasite/BrowserPal.html";
key[i]	= "CLSID\{5F5564AC-DE7A-4DCD-9296-32E71A35DCB7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bptlb.dll";

i++;
name[i]	= "Adlogix.com Zamingo adware";
url[i]	= "http://www.spyany.com/program/article_adw_rm_Zamingo.html";
key[i]	= "CLSID\{5FA6752A-C4A0-4222-88C2-928AE5AB4966}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SWin32.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{60112085-E1CE-4e0e-823A-EBB1AD98804C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Naupoint toolbar";
url[i]	= "http://doxdesk.com/parasite/Naupoint.html";
key[i]	= "CLSID\{60261C06-81B0-4DE0-9313-E5BA203A64E9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pdfmgr.dll";

i++;
name[i]	= "Netpal";
url[i]	= "http://www.doxdesk.com/parasite/NetPal.html";
key[i]	= "CLSID\{6085FB5B-C281-4B9C-8E5D-D2792EA30D2F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Netpal.dll";

i++;
name[i]	= "iGetNet/Natural Language Navigation";
url[i]	= "http://www.doxdesk.com/parasite/IGetNet.html";
key[i]	= "CLSID\{60E78CAC-E9A7-4302-B9EE-8582EDE22FBF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BHO001.DLL";

i++;
name[i]	= "i-lookup search bar";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{61D029AC-972B-49FE-A155-962DFA0A37BB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ineb.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{62160EEF-9D84-4C19-B7B8-6AC2526CD726}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Matrix Technology Network 123Mania";
url[i]	= "http://www.pestpatrol.com/pestinfo/other/123_messenger.asp";
key[i]	= "CLSID\{622CC208-B014-4FE0-801B-874A5E5E403A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "GIDCAI32.DLL";

i++;
name[i]	= "CnsMin";
url[i]	= "http://www.doxdesk.com/parasite/CnsMin.html";
key[i]	= "CLSID\{6231D512-E4A4-4DF2-BE62-5B8F0EE348EF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "cesweb.dll";

i++;
name[i]	= "Stingware GuardBar";
url[i]	= "http://www.guardbar.com/";
key[i]	= "CLSID\{62F5BBB6-A71E-46E7-AE78-73D25185EDC8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "GuardBar.dll";

i++;
name[i]	= "Townews.com adware";
url[i]	= "";
key[i]	= "CLSID\{634EFDE4-087D-4ce9-952F-63C9EEB2E0BF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WNDPOS~1.DLL";

i++;
name[i]	= "Naupoint toolbar";
url[i]	= "http://doxdesk.com/parasite/Naupoint.html";
key[i]	= "CLSID\{6375B3AD-4440-4C1F-95E5-A24198ED671C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sp1.dll";

i++;
name[i]	= "Huntbar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{63B78BC1-A711-4D46-AD2F-C581AC420D41}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Btiein.dll";

i++;
name[i] = "FlashTrack, Ftapp";
url[i]	= "http://www.doxdesk.com/parasite/FlashTrack.html";
key[i]	= "CLSID\{63CF97E8-4133-438a-A831-CC9C6D47D673}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Flcp.dll";

i++;
name[i]	= "Win32/Aspam.Trojan";
url[i]	= "http://www.doxdesk.com/parasite/ASpam.html";
key[i]	= "CLSID\{657B9354-BB3B-4500-A9B0-109B4FA64815}\InprocServer32";
item[i]	= NULL;
exp[i]	= "amcis32.dll";

i++;
name[i]	= "Commander Toolbar";
url[i]	= "";
key[i]	= "CLSID\{6596829B-37D4-40ad-971B-1E9041725C52}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ietb.dll";

i++;
name[i]	= "PeopleOnPage/AproposMedia";
url[i]	= "http://www.doxdesk.com/parasite/AproposMedia.html";
key[i]	= "CLSID\{65C8C1F5-230E-4DC9-9A0D-F3159A5E7778}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pop";

i++;
name[i]	= "OpinionBar";
url[i]	= "http://www.earncashontheinternet.com/paidtosurf/review/opinionbar.asp";
key[i]	= "CLSID\{6607C683-AE7C-11D4-ACD7-0050DAC291A2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Myiemonitor.dll";

i++;
name[i]	= "Commonname toolbar";
url[i]	= "http://www.doxdesk.com/parasite/CommonName.html";
key[i]	= "CLSID\{6656B666-992F-4D74-8588-8CAC9E79D90C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CNBabe.dll";

i++;
name[i] = "FlashTrack, Ftapp";
url[i]	= "http://www.doxdesk.com/parasite/FlashTrack.html";
key[i]	= "CLSID\{665ACD90-4541-4836-9FE4-062386BB8F05}\InprocServer32";
item[i]	= NULL;
exp[i]	= "F";
#Flt.dll, Ftapp.dll

i++;
name[i]	= "LinkReplacer";
url[i]	= "http://www.doxdesk.com/parasite/LinkReplacer.html";
key[i]	= "CLSID\{66993893-61B8-47DC-B10D-21E0C86DD9C8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iehelper.dll";

i++;
name[i]	= "Whazit";
url[i]	= "http://www.doxdesk.com/parasite/Whazit.html";
key[i]	= "CLSID\{66F67511-2665-4C34-9E20-FAC2C0954EF2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "whattt.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{68132581-10F2-416E-B188-4E648075325A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "PrecisionPop adware";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.precisionpop.html";
key[i]	= "CLSID\{68513770-A18E-11D7-B77C-00C0DFF3F600}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Helper.dll";

i++;
name[i]	= "IEplugin";
url[i]	= "http://www.doxdesk.com/parasite/IEPlugin.html";
key[i]	= "CLSID\{69135BDE-5FDC-4B61-98AA-82AD2091BCCC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "systb.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{6A06CDAD-9D2D-42A0-9C91-C0CF7CB9971B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "LinkReplacer hijacker variant";
url[i]	= "http://www.doxdesk.com/parasite/LinkReplacer.html";
key[i]	= "CLSID\{6A6E50DC-BFA8-4B40-AB1B-159E03E829FD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "lmf32.dll";

i++;
name[i]	= "eAcceleration StopSign";
url[i]	= "http://www.doxdesk.com/parasite/DownloadReceiver.html";
key[i]	= "CLSID\{6ACD11BD-4CA0-4283-A8D8-872B9BA289B6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "webcbrowse.dll";

i++;
name[i]	= "Alexa Toolbar";
url[i]	= "http://pages.alexa.com/prod_serv/quicktour_new.html";
key[i]	= "CLSID\{6AF9BC61-3CC5-42A7-82D1-FFC2562A7289}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Alxie328.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{6B12DABB-0B7C-44FA-B0B3-4BAFF3790256}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iexplorr24.dll";

i++;
name[i]	= "Winshow/Searchv.com hijacker";
url[i]	= "http://www.doxdesk.com/parasite/Winshow.html";
key[i]	= "CLSID\{6CC1C918-AE8B-4373-A5B4-28BA1851E39A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winshow.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{6CC1C91A-AE8B-4373-A5B4-28BA1851E39A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winlink.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{6CDF3C49-20E6-48d7-811B-9F5DD17F1D90}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sfg****.dll";

i++;
name[i]	= "Comet Cursor";
url[i]	= "http://www.doxdesk.com/parasite/CometCursor.html";
key[i]	= "CLSID\{6D0AC7F7-B628-4581-A8B2-14D97F24AA76}\InprocServer32";
item[i]	= NULL;
exp[i]	= "brbho.dll";

i++;
name[i]	= "BrowserAid/ABCSearch";
url[i]	= "http://www.doxdesk.com/parasite/CashToolbar.html";
key[i]	= "CLSID\{6D55490C-1BD4-4790-BA31-84D261316E28}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Highlighthelper.dll";

i++;
name[i]	= "suspected keyword hijacker";
url[i]	= "http://computercops.biz/postlite89308-.html";
key[i]	= "CLSID\{6D9F42B8-B7E5-4BB9-9A13-CAE53D44196E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "searcher.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{6E1C5E3D-A8E6-4a92-820F-BFCFE45BA158}\InprocServer32";
item[i]	= NULL;
exp[i]	= "veev";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{6E34D984-4054-45E3-8452-0159A2F0D232}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Veevo.dll";

i++;
name[i]	= "FriendGreetings E-Card foistware";
url[i]	= "http://vil.nai.com/vil/content/v_99760.htm";
key[i]	= "CLSID\{7011471D-3F74-498E-88E1-C0491200312D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Otglove.dll";

i++;
name[i]	= "Xupiter Orbitexplorer";
url[i]	= "http://www.doxdesk.com/parasite/Xupiter.html";
key[i]	= "CLSID\{702AD576-FDDB-4d0f-9811-A43252064684}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Toolbar.dll";

i++;
name[i]	= "TV Media/CleverIEHooker";
url[i]	= "http://www.pestpatrol.com/PestInfo/c/cleveriehooker.asp";
key[i]	= "CLSID\{707E6F76-9FFB-4920-A976-EA101271BC25}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Jeired.dll";

i++;
name[i]	= "HDTbar";
url[i]	= "http://www.spynet.com/spyware/spyware-HDTBar.aspx";
key[i]	= "CLSID\{70B3DA2C-E02D-4ce0-B1F8-48320FD443D2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "T2BHO.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{710089CF-87C3-763F-C8F6-5A0DBFD3AEC3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Multiple file names";

i++;
name[i]	= "321search.com search hijacker";
url[i]	= "";
key[i]	= "CLSID\{7148369a-1105-4e85-83e0-085e784ba374}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SearchAssistant.dll";

i++;
name[i]	= "Blazefind IESearchbar";
url[i]	= "http://www.kephyr.com/spywarescanner/library/iesearchbar/index.phtml";
key[i]	= "CLSID\{71ED4FBA-4024-4bbe-91DC-9704C93F453E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iesearchbar.dll";

i++;
name[i]	= "NeoToolbar";
url[i]	= "http://doxdesk.com/parasite/NeoToolbar.html";
key[i]	= "CLSID\{722E8B26-1C44-460F-88BB-50C82B20E30E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msqsb.dll";

i++;
name[i]	= "LoveTester foistware";
url[i]	= "http://spamwatch.codefish.net.au/modules.php?op=modload&name=News&file=index&catid=&topic=24";
key[i]	= "CLSID\{72557F9F-13AE-44C9-B3D7-5091B599027C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "smail11.dll";

i++;
name[i]	= "ZeroPopupBar";
url[i]	= "http://www.doxdesk.com/parasite/ZeroPopUp.html";
key[i]	= "CLSID\{72A58725-2635-4725-8C53-676DFD1FEB8D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "zeropopupbar.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{72AC6865-B1D3-4C32-A27B-4B3BF04DE655}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "IGN Keywords";
url[i]	= "http://www.doxdesk.com/parasite/IGetNet.html";
key[i]	= "CLSID\{730F2451-A3FE-4A72-938C-FC8A74F15978}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bho.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{73529697-D46A-4F7D-8A93-01378FCAEDA4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "FlashTrack";
url[i]	= "http://www.pestpatrol.com/PestInfo/F/FlashTrack.asp";
key[i]	= "CLSID\{7371F073-AC0F-4b80-BB2F-96A488CEFB32}\InprocServer32";
item[i]	= NULL;
exp[i]	= "xm320.dll";

i++;
name[i]	= "SafeSurfing parasite variant";
url[i]	= "http://pestpatrol.com/pestinfo/s/safesurfing.asp";
key[i]	= "CLSID\{7412C042-43B8-4F63-AEF3-E786DFAD1484}\InprocServer32";
item[i]	= NULL;
exp[i]	= "imwire28.dll";

i++;
name[i]	= "Kugoo IEHelper";
url[i]	= "http://www.pestpatrol.com/PestInfo/i/iehelper_dll.asp";
key[i]	= "CLSID\{748A5D0A-68D3-11D4-A67E-00E098823A80}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iehelper.dll";

i++;
name[i]	= "i-Lookup/Bmeb";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{753AA023-02D1-447D-8B55-53A91A5ABF18}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bmeb.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{75A46C7E-D7AB-55F3-8DF2-D9A7FFD913E6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Multiple file names";

i++;
name[i]	= "EZCybersearch bar";
url[i]	= "http://www.doxdesk.com/parasite/ezCyberSearch.html";
key[i]	= "CLSID\{760A9DDE-1433-4A7C-8189-D6735BB5D3DD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "EzSearch.dll";

i++;
name[i]	= "GoGoTools";
url[i]	= "http://doxdesk.com/parasite/GogoTools.html parasite";
key[i]	= "CLSID\{76532682-A5C9-11d8-AE07-00D0591}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SearchGogo.dll";

i++;
name[i]	= "Qcbar/AdultLinks";
url[i]	= "http://www.doxdesk.com/parasite/AdultLinks.html";
key[i]	= "CLSID\{765E6B09-6832-4738-BDBE-25F226BA2AB0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "allch.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{77849D67-5672-4B68-93E2-CCEFF1E3949E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "BrowserAid/Startium variant";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{778C2A73-4707-41d1-9269-03FF7DE5FFB8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "D3D869D4.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{79369D5C-2903-4b7a-ADE2-D5E0DEE14D24}\InprocServer32";
item[i]	= NULL;
exp[i]	= "GoogleMS.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.spywareinfo.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{799A370D-5993-4887-9DF7-0A4756A77D00}\InprocServer32";
item[i]	= NULL;
exp[i]	= "search.dll";

i++;
name[i]	= "FastFind adware variant";
url[i]	= "http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_STARTPAG.KF&VSect=T";
key[i]	= "CLSID\{79C03BC5-6C55-4B5B-921F-C02B6F1ABD7B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Pribi.dll";

i++;
name[i]	= "NovaPortal adware";
url[i]	= "http://www.clickz.com/news/article.php/177951";
key[i]	= "CLSID\{79C9FB71-7827-11D3-8DF7-00105A119B7C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NPBH.dll";

i++;
name[i]	= "Adware.Sa";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.sa.html";
key[i]	= "CLSID\{7B55BB05-0B4D-44fd-81A6-B136188F5DEB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "questmod.dll";

i++;
name[i]	= "FlashEnhancer";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.flashenhancer.html";
key[i]	= "CLSID\{7CD20E91-1F31-41da-8379-479EA31DF969}\InprocServer32";
item[i]	= NULL;
exp[i]	= "XML.dll";

i++;
name[i]	= "Foxxweb Interactive (Softomate) spyware - Foxxweb Interactive (spyware)";
url[i]	= "";
key[i]	= "CLSID\{7D6BEC01-15E2-46F0-8ED3-D715DE09A8F9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "";

i++;
name[i]	= "DailyWinner Prize Bar";
url[i]	= "http://www.doxdesk.com/parasite/DailyWinner.html";
key[i]	= "CLSID\{7DD896A9-7AEB-430F-955B-CD125604FDCB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Veg32.dll";

i++;
name[i]	= "Backdoor.Berbew.P";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.p.html";
key[i]	= "CLSID\{7EFFAAFF-EA0A-1A3A-CBCD-F13522D53649}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Adpowerzone.com keyword hijacker";
url[i]	= "";
key[i]	= "CLSID\{7FC56022-4EDA-472E-8830-7CA92CCBD025}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ServerSide.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.spywareinfo.com/~merijn/cwschronicles.html";
key[i]	= "CLSID\{7FE49EAE-AA38-4044-9D10-09DAB477051F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "popup_bl.dll";

i++;
name[i]	= "BrowserAid/Rundll16";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{80672997-D58C-4190-9843-C6C61AF8FE97}\InprocServer32";
item[i]	= NULL;
exp[i]	= "rundll16.dll";

i++;
name[i] = "Hijacker, as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{8085E374-ACBB-42F9-873F-49EC7E244F97}\InprocServer32";
item[i]	= NULL;
exp[i]	= "";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{8109AF33-6949-4833-8881-43DCC232B7B2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i] = "PASSGRAB, a spam relayer, hijacker and email account password stealer";
url[i]	= "";
key[i]	= "CLSID\{81A35F39-4850-474E-92C9-B4CF283207E0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mstask64.dll";

i++;
name[i]	= "Adware DAE.A";
url[i]	= "http://www.trendmicro.com/vinfo/grayware/graywareDetails.asp?SNAME=ADW_DAE.A";
key[i]	= "CLSID\{81A99149-F047-4090-8AAD-D11FF4EFB734}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dae.dll";

i++;
name[i]	= "Adware.Margoc variant";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.margoc.html";
key[i]	= "CLSID\{81D66134-ADC3-4C6D-B0A9-03D4EE35B849}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "New.Net QuickSearch";
url[i]	= "http://doxdesk.com/parasite/NewDotNet.html";
key[i]	= "CLSID\{82315A18-6CFB-44a7-BDFD-90E36537C252}\InprocServer32";
item[i]	= NULL;
exp[i]	= "QuickSearchBar";

i++;
name[i]	= "EliteBar/SearchMiracle adware";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-SearchMiracle.EliteBar.aspx";
key[i]	= "CLSID\{825CF5BD-8862-4430-B771-0C15C5CA880F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Elitebar.dll";

i++;
name[i]	= "Flyswat";
url[i]	= "http://accs-net.com/smallfish/flyswat.htm";
key[i]	= "CLSID\{82B98006-7A56-11D2-A26F-00C04F962769}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Flylib.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{82E8FF5B-20DA-4F43-9787-09FA534B7627}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i] = "Hijacker,  as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{832BEBED-C3DA-4534-A2C2-B2FFF220C820}\InprocServer32";
item[i]	= NULL;
exp[i]	= "replaceSearch.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{834261E1-DD97-4177-853B-C907E5D5BD6E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dpe.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{83B3E0C1-DEF1-4df5-A3F5-92D10B7A396A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sfg";

i++;
name[i]	= "ClearStream Accelerator";
url[i]	= "http://www.spyany.com/program/article_spw_rm_ClearStream_Accelerator.html";
key[i]	= "CLSID\{83DC91DB-7896-43E3-B34D-A7D043F16BB1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "rdsa.dll";

i++;
name[i]	= "BlazeFind Websearch";
url[i]	= "http://www.spywareguide.com/product_show.php?id=724";
key[i]	= "CLSID\{83DE62E0-5805-11D8-9B25-00E04C60FAF2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "2_0_1browserhelper2.dll";

i++;
name[i]	= "P0rn related malware";
url[i]	= "";
key[i]	= "CLSID\{8403CB53-12B3-4537-9DEC-4F12F70A883D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "thehun.dll";

i++;
name[i]	= "AlibabaIEToolBar";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-AlibabaIEToolBar.aspx";
key[i]	= "CLSID\{850B69E4-90DB-4F45-8621-891BF35A5B53}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bar.dll";

i++;
name[i]	= "eZsearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{858126B0-3708-4051-AE8E-B48521401CA2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ctsr*.dll";

i++;
name[i]	= "Medialoads Enhanced/Downloadware";
url[i]	= "http://www.doxdesk.com/parasite/DownloadWare.html";
key[i]	= "CLSID\{85A702BA-EA8F-4B83-AA07-07A5186ACD7E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ME";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{85CBFDE0-B26B-4EE5-BD3C-4DE111DE763E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Winnet.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{870B70D4-F6DA-47AE-9158-D146440A0A4D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "HuntBar/Wintools";
url[i]	= "http://doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{87766247-311C-43B4-8499-3D5FEC94A183}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WToolsB.dll";

i++;
name[i]	= "BandObjects/eStart";
url[i]	= "http://www.doxdesk.com/parasite/eStart.html";
key[i]	= "CLSID\{8786386E-4B22-11D6-9C60-E5DA06D87378}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BandObjs1,0,0,1.dll";

i++;
name[i]	= "searchingall.com/onedollaremail.com pay-per-click foistware";
url[i]	= "";
key[i]	= "CLSID\{88F0297D-A046-4942-B6B9-03D8939E92D5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DeskwareDownloader.dll";

i++;
name[i]	= "HuntBar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{8952A998-1E7E-4716-B23D-3DBE03910972}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Toolbar.dll";

i++;
name[i]	= "Xlocator/WinLocator adware";
url[i]	= "http://www.kephyr.com/spywarescanner/library/xlocator/index.phtml";
key[i]	= "CLSID\{89AEAB46-8E8A-4045-9003-5614BFBFE90B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Winlocatorhelper.dll";

i++;
name[i]	= "NetNucleus/Mirar webband";
url[i]	= "http://www.kephyr.com/spywarescanner/library/mirartoolbar/index.phtml";
key[i]	= "CLSID\{8A0DCBDA-6E20-489C-9041-C1E8A0352E75}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NN_Bar.dll";

i++;
name[i]	= "Mega! Search:  best-search.us hijacker";
url[i]	= "";
key[i]	= "CLSID\{8BC6346B-FFB0-4435-ACE3-FACA6CD77816}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MegaHost.dll";

i++;
name[i] = "HuntBar/WinTools, adware variant";
url[i]	= "http://doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{8DA5457F-A8AA-4CCF-A842-70E6FD274094}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WToolsT.dll";

i++;
name[i]	= "ezSearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{8DB672BD-330F-11D8-8168-00C02623048A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Testadit.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html ";
key[i]	= "CLSID\{8E9C4F32-BD3F-4C49-9AF5-3F4C5D32EBD7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mbho.dll";

i++;
name[i]	= "MoneyTree/DyFuCa";
url[i]	= "http://www.doxdesk.com/parasite/MoneyTree.html";
key[i]	= "CLSID\{8F4E5661-F99E-4B3E-8D85-0EA71C0748E4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Wsem";

i++;
name[i]	= "i-search.us hijacker";
url[i]	= "";
key[i]	= "CLSID\{8F5A62E2-71F2-72D3-E045-DDF234CAE228}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Isearch2.dll";

i++;
name[i]	= "FizzleWizzle search bar";
url[i]	= "";
key[i]	= "CLSID\{9056A11F-5EA6-4A67-BDE9-8D3C7C453DAC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iefwbar.dll";

i++;
name[i]	= "SearchSquire";
url[i]	= "http://www.doxdesk.com/parasite/SearchSquire.html";
key[i]	= "CLSID\{907CA0E5-CE84-11D6-9508-02608CDD2841}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SEARCH~2.DLL";

i++;
name[i]	= "SearchSquire";
url[i]	= "http://www.doxdesk.com/parasite/SearchSquire.html";
key[i]	= "CLSID\{907CA0E5-CE84-11D6-9508-02608CDD2842}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SearchSquire2.dll";

i++;
name[i]	= "SearchSquire";
url[i]	= "http://doxdesk.com/parasite/SearchSquire.html";
key[i]	= "CLSID\{907CA0E5-CE84-11D6-9508-02608CDD2846}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SearchUpdate33.dll";

i++;
name[i]	= "SubSearch";
url[i]	= "http://www.doxdesk.com/parasite/SubSearch.html";
key[i]	= "CLSID\{90DA654C-083C-11D6-8A9D-0050BA8452C0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sbsrch_v2.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{90E34F98-E3E6-4CD7-A592-E964FED8AF78}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr26.dll";

i++;
name[i]	= "IEPlugin";
url[i]	= "http://www.doxdesk.com/parasite/IEPlugin.html";
key[i]	= "CLSID\{914AFB33-550B-4BD0-B4EF-8DA185504836}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Winobject.dll";

i++;
name[i]	= "Trojan.Goldun.B";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.goldun.b.html";
key[i]	= "CLSID\{92617934-9abc-def0-0fed-fad48c654321}\InprocServer32";
item[i]	= NULL;
exp[i]	= NULL;

i++;
name[i]	= "ActualNames SearchPike";
url[i]	= "http://www.doxdesk.com/parasite/ActualNames.html";
key[i]	= "CLSID\{92C7D65C-52F3-4545-8A35-213D730DB1ED}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Spredirect.dll";

i++;
name[i]	= "AdBlaster";
url[i]	= "http://www.xblock.com/product_show.php?id=787";
key[i]	= "CLSID\{941CA48C-3984-4E7D-AAF8-8755ED76EB50}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{94326E3F-F51F-4863-A832-4ACD0D7D4BC3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr27.dll";

i++;
name[i]	= "ClearSearch";
url[i]	= "http://doxdesk.com/parasite/ClearSearch.html";
key[i]	= "CLSID\{947E6D5A-4B9F-4CF4-91B3-562CA8D03313}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IE_ClrSch.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{94927A13-4AAA-476A-989D-392456427688}\InprocServer32";
item[i]	= NULL;
exp[i]	= "urlcli";

i++;
name[i]	= "FlashTrack parasite";
url[i]	= "http://doxdesk.com/parasite/FlashTrack.html";
key[i]	= "CLSID\{95795B67-BBAB-47d0-8A9F-069E8242C0E5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Fen.dll";

i++;
name[i]	= "Superlogy.com hijacker";
url[i]	= "";
key[i]	= "CLSID\{95E02C52-05FC-425D-8378-9DA70F9CD763}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Aadl.dll";

i++;
name[i]	= "Top-banners.com adware";
url[i]	= "";
key[i]	= "CLSID\{968BC8A3-7660-4B12-B2BF-3334775835E1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "KGhost.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{96BE1D9A-9E54-4344-A27A-37C088D64FB4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dnsrep";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{96BE1D9A-9E54-4344-A27A-37C088D64FB4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mseffm.dll";

i++;
name[i]	= "Comet Cursor";
url[i]	= "http://www.doxdesk.com/parasite/CometCursor.html";
key[i]	= "CLSID\{96DA5BEE-4ACC-476C-B3EC-54C6730C4293}\InprocServer32";
item[i]	= NULL;
exp[i]	= "brbho.dll";

i++;
name[i]	= "Dynamic Desktop Media adware variant";
url[i]	= "http://www.pestpatrol.com/PestInfo/d/dynamic_desktop_media.asp";
key[i]	= "CLSID\{9819C369-5F62-4D37-9A42-44043A742C1E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "redirect.dll";

i++;
name[i]	= "Adware.Admess";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.admess.html";
key[i]	= "CLSID\{9896231A-C487-43A5-8369-6EC9B0A96CC0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WStart.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{98D7B53E-B1D2-4755-B0A4-703E18FF91E8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "M030106SHOP.DLL";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{98DBBF16-CA43-4c33-BE80-99E6694468A4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msole.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{99D764FC-CDD7-00B8-618D-0880E43E5DFC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "from imu.com.cn";
url[i]	= "";
key[i]	= "CLSID\{9A0527C1-4D5F-4e45-9D28-6257F75EDDB1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "imuiepls.dll";

i++;
name[i]	= "NetNucleus/Mirar webband";
url[i]	= "http://www.pestpatrol.com/pestinfo/n/nn_bar.asp";
key[i]	= "CLSID\{9A9C9B69-F908-4AAB-8D0C-10EA8997F37E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WinNB";

i++;
name[i]	= "Matrix Technology Network 123Mania";
url[i]	= "http://www.pestpatrol.com/pestinfo/other/123_messenger.asp";
key[i]	= "CLSID\{9C5B2F29-1F46-4639-A6B4-828942301D3E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SIPSPI32.DLL";

i++;
name[i]	= "Adware.WinFavorites";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.winfavorites.html";
key[i]	= "CLSID\{9C691A33-7DDA-4C2F-BE4C-C176083F35CF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bridge.dll";

i++;
name[i]	= "RedV Protector Suite";
url[i]	= "http://services.bee.net/redv/protectorsuite/";
key[i]	= "CLSID\{9C777253-3E17-42d6-897A-11B8617A8F7C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IELib.dll";

i++;
name[i]	= "MSN SmartTags";
url[i]	= "http://www.zdnet.com/anchordesk/stories/story/0,10738,2771967,00.html";
key[i]	= "CLSID\{9DD4258A-7138-49C4-8D34-587879A5C7A4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msnbho.dll";

i++;
name[i]	= "FastFind adware variant";
url[i]	= "http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_STARTPAG.KF&VSect=T";
key[i]	= "CLSID\{9E992732-295F-4987-8BE3-16FAC1639198}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IEService.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{9EAC0102-5E61-2312-BC2D-414456544F4E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ADV.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{9EAC0102-5E61-2312-BC2D-444C4C4F5552}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DLL.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{9EAC0102-5E61-2312-BC2D-4D54434D5443}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mtc.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{9EAC0102-5E61-2312-BC2D-4E4153202020}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NAS.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{9EAC0102-5E61-2312-BC2D-544243544243}\InprocServer32";
item[i]	= NULL;
exp[i]	= "TBC.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{9EAC0102-5E61-2312-BC2D-76746C56544C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "vtlbar1.dll";

i++;
name[i]	= "Windows Search Bar hijacker";
url[i]	= "http://www.pestpatrol.com/PestInfo/w/windows_search_bar.asp";
key[i]	= "CLSID\{9FB534E3-67CB-4307-AE0A-9E8B5581BE2C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WinSB.dll";

i++;
name[i]	= "iLookup parasite variant";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{9FF528A9-7314-4658-B497-3D1D4597B300}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wingss32.dll";

i++;
name[i]	= "IncrediFind variant";
url[i]	= "http://www.doxdesk.com/parasite/KeenValue.html";
key[i]	= "CLSID\{A045DC85-FC44-45be-8A50-E4F9C62C9A84}\InprocServer32";
item[i]	= NULL;
exp[i]	= "PerfectNavBHO.dll";

i++;
name[i]	= "SearchFu/123Search";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/search123.asp";
key[i]	= "CLSID\{A096A159-4E58-45A9-8EE6-B11466851181}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msietk1020.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{A097840A-61F8-4B89-8693-F68F641CC838}\InprocServer32";
item[i]	= NULL;
exp[i]	= "urlcli";

i++;
name[i]	= "Searchex";
url[i]	= "http://www.doxdesk.com/parasite/Searchex.html";
key[i]	= "CLSID\{A116A5C1-AD77-446C-992A-F56200B112DB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Homepage.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{A23AB93D-6CFF-442c-BB8A-41F6145F47E7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "PDF";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{A2833482-B023-4C65-B09D-EE47A4E8CC56}\InprocServer32";
item[i]	= NULL;
exp[i]	= "botnet1.dll";

i++;
name[i]	= " BonziBuddy";
url[i]	= "http://accs-net.com/smallfish/bonzi.htm ";
key[i]	= "CLSID\{A28C2A31-3AB0-4118-922F-F6B3184F5495}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WebCompass.dll";

i++;
name[i]	= "Adware.IESP.mht/CasinoPalazzo foistware";
url[i]	= "http://www.bluestack.org/Iesp.Mht?show_comments=1";
key[i]	= "CLSID\{A3DFDA85-1D92-4E28-8C0C-522574ACDC8A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msacrohlp.dll";

i++;
name[i]	= "IS Technologies SideFind";
url[i]	= "http://www.sophos.com/virusinfo/analyses/trojistbarm.html";
key[i]	= "CLSID\{A3FDD654-A057-4971-9844-4ED8E67DBBB8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sfbho.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{A44B961C-8C36-470f-8555-EDA0EFC1E710}\InprocServer32";
item[i]	= NULL;
exp[i]	= "popupblocker.dll";

i++;
name[i]	= "Troj/Bdoor-CLS";
url[i]	= "http://www.sophos.com/virusinfo/analyses/trojbdoorcls.html";
key[i]	= "CLSID\{A452DA63-4286-48EB-A838-3BA85C3049F5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Acrobat.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{A5366673-E8CA-11D3-9CD9-0090271D075B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msacmx.dll";

i++;
name[i]	= "Httper";
url[i]	= "http://www.doxdesk.com/parasite/Httper.html";
key[i]	= "CLSID\{A5483501-070C-41DD-AF44-9BD8864B3015}\InprocServer32";
item[i]	= NULL;
exp[i]	= "httper.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{A55581DC-2CDB-4089-8878-71A080B22342}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Autosearch.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{A5E0B170-04FA-11d1-B7DA-00A0C90348D6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msdocvw.dll";

i++;
name[i]	= "Huntbar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{A6250FB8-2206-499E-A7AA-E1EC437E71C0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msielink.dll";

i++;
name[i]	= "Commonname toolbar";
url[i]	= "http://www.doxdesk.com/parasite/CommonName.html";
key[i]	= "CLSID\{A6475E6B-3C2E-4B1F-82FD-8F1C0B1D8AD0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BabeIE.dll";

i++;
name[i]	= "Trojan.Magise";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.magise.html";
key[i]	= "CLSID\{A6790AA5-C6C7-4BCF-A46D-0FDAC4EA90EB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msearch.dll";

i++;
name[i]	= "Adware.IEPageHelper";
url[i]	= "http://www.pestpatrol.com/pestinfo/a/adware_iepagehelper.asp";
key[i]	= "CLSID\{A6F42CAD-2559-48DF-AF30-89E480AF5DFA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bho.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{A76066C9-941B-4209-9D96-0AC80501100D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr11.dll";

i++;
name[i]	= "Adtomi adware variant";
url[i]	= "http://safersite.net/pestinfo%5Ca%5Cadtomi.asp";
key[i]	= "CLSID\{A78860C8-EE1A-46DF-A97F-E3E6D433E80B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Clickspring/PurityScan";
url[i]	= "http://doxdesk.com/parasite/PurityScan.html";
key[i]	= "CLSID\{A78CC2FF-6E4E-4556-B27C-D7C3A70D7A50}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NDrv.dll";

i++;
name[i]	= "BookedSpace";
url[i]	= "http://www.doxdesk.com/parasite/BookedSpace.html";
key[i]	= "CLSID\{A85C4A1B-BD36-44E5-A70F-8EC347D9B24F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bs3.dll";

i++;
name[i]	= "HighTraffic";
url[i]	= "http://www.doxdesk.com/parasite/HighTraffic.html";
key[i]	= "CLSID\{A8B9F08F-2FC4-4ADE-9049-CFBA586971BA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bho2.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{A903BF95-883E-4E70-AEC8-6C27CDC0A6B2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{A9A674BF-771F-42E5-A440-D20DDA85A862}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "CheckUrl";
url[i]	= "";
key[i]	= "CLSID\{A9EEF0D7-5695-45BA-8943-ED3B95A50BD2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CheckUrl.dll";

i++;
name[i]	= "ClearStream Accelerator";
url[i]	= "http://www.spyany.com/program/article_spw_rm_ClearStream_Accelerator.html";
key[i]	= "CLSID\{AC109D01-32D6-4EB5-8300-D3C5EBAC7C83}\InprocServer32";
item[i]	= NULL;
exp[i]	= "X2ff.dll";

i++;
name[i]	= "Adware.Slagent";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.simcss.b.html";
key[i]	= "CLSID\{ACB3E0B7-7D0C-40B7-99B3-3EEACDF86BFB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "4b_1,0,1,1_mslagent.dll";

i++;
name[i]	= "eXact Advertising";
url[i]	= "http://www.doxdesk.com/parasite/BargainBuddy.html";
key[i]	= "CLSID\{AEECBFDA-12FA-4881-BDCE-8C3E1CE4B344}\InprocServer32";
item[i]	= NULL;
exp[i]	= "nvms.dll";

i++;
name[i]	= "ezSearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{AEFCDEC8-EB7D-429F-BC73-4F30D07BFE41}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ctadl";

i++;
name[i]	= "Hotbar";
url[i]	= "http://www.doxdesk.com/parasite/HotBar.html";
key[i]	= "CLSID\{B195B3B3-8A05-11D3-97A4-0004ACA6948E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Hbhostie.dll";

i++;
name[i]	= "t2t2.com toolbar by Chengwei Ventures LLC";
url[i]	= "";
key[i]	= "CLSID\{B1D147E7-873E-4909-8127-695D9BB78728}\InprocServer32";
item[i]	= NULL;
exp[i]	= "barhelp.dll";

i++;
name[i]	= "Kugoo IEHelper";
url[i]	= "http://www.pestpatrol.com/PestInfo/i/iehelper_dll.asp";
key[i]	= "CLSID\{B3ECCAC9-C7FA-462C-894B-8E9930A70E14}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IEHelper";

i++;
name[i]	= "Searchex";
url[i]	= "http://www.doxdesk.com/parasite/Searchex.html";
key[i]	= "CLSID\{B405EE45-1AA2-410D-A6CF-1A74371DCD62}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Hotlink.dll";

i++;
name[i]	= "iChoose browser enhancement";
url[i]	= "http://www.luckysoftware.dk/ichoose.php";
key[i]	= "CLSID\{B40A6610-1D16-11D3-80B2-005004994DA2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bpieclient.dll";

i++;
name[i]	= "Adware.Adtomi";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.adtomi.html";
key[i]	= "CLSID\{B549456D-F5D0-4641-BCED-8648A0C13D83}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BrowserHelper.dll";

i++;
name[i]	= "BaiDu toolbar";
url[i]	= "";
key[i]	= "CLSID\{B580CF65-E151-49C3-B73F-70B13FCA8E86}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BaiDuBar.dll";

i++;
name[i]	= "EZSearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{B6598677-4B54-42A9-BA67-8B64E3FCD92D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "psic";

i++;
name[i]	= "Troj/StartPa-DW hijacker variant";
url[i]	= "http://www.sophos.com/virusinfo/analyses/trojstartpadw.html";
key[i]	= "CLSID\{B72F75B8-93F3-429D-B13E-660B206D897A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "beem.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{B824E7B0-E8E3-4D75-895E-2C309EA4CC5D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Sgpopupblocker.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{B847676D-72AC-4393-BFFF-43A1EB979352}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wcadw.dll";

i++;
name[i]	= "MediaUpdate";
url[i]	= "http://www.doxdesk.com/parasite/MediaUpdate.html";
key[i]	= "CLSID\{B8C0220D-763D-49A4-95F4-61DFDEC66EE6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MEDUP012.DLL";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{B957F25D-F812-44c4-A23C-249CCFE0AAE0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msnet.dll";

i++;
name[i]	= "Netster Smart Browse Toolbar";
url[i]	= "http://at.netster.com/Index.asp?Site=YXQubmV0c3Rlci5jb20%3D";
key[i]	= "CLSID\{B98F79F4-3619-49FB-A7E7-B737E58C5727}\InprocServer32";
item[i]	= NULL;
exp[i]	= "netster.dll";

i++;
name[i]	= "CashSaver spyware";
url[i]	= "http://auction.ahnlab.com/badcode_info_view.asp?list=/badcode_info_list.asp&seq=1551";
key[i]	= "CLSID\{B9ADBF45-B136-4FC5-8582-48C2A22600CE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "cashsaverbho.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{B9D90B27-AD4A-413a-88CB-3E6DDC10DC2D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "MSOPT.DLL";

i++;
name[i]	= "GoHip/Browserenh";
url[i]	= "http://www.gohip.com/";
key[i]	= "CLSID\{BA3D9F56-5EC1-497D-881A-93A28F58D9AD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IE.dll";

i++;
name[i]	= "Icoo Loader";
url[i]	= "http://www.by-users.co.uk/forums/?board=help&action=display&num=1085918311";
key[i]	= "CLSID\{BA7270AE-5636-4618-BAF3-F86ADA39F036}\InprocServer32";
item[i]	= NULL;
exp[i]	= "icoourl.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{ba77911b-a393-4a2e-b5b5-5b8ed17d7b43}\InprocServer32";
item[i]	= NULL;
exp[i]	= "disable1.dll";

i++;
name[i]	= "Divago Surfairy";
url[i]	= "http://www.doxdesk.com/parasite/Surfairy.html";
key[i]	= "CLSID\{BB9AAAF3-4F8D-48B5-A565-FF3E58433DC2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SurfairyHlp.dll";

i++;
name[i]	= "InetSpeak/Iexplorr";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{BC0D2038-2DE5-4A6F-92BC-B18A3E0DE32A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iexplorr11.dll";

i++;
name[i]	= "BDPLugin";
url[i]	= "http://www.spyany.com/program/article_adw_rm_BDHelper.html";
key[i]	= "CLSID\{BC207F7D-3E63-4ACA-99B5-FB5F8428200C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bdsrhook.dll";

i++;
name[i]	= "Adware.HungryHands";
url[i]	= "http://sarc.com/avcenter/venc/data/pf/adware.hungryhands.html";
key[i]	= "CLSID\{BCF96FB4-5F1B-497B-AECC-910304A55011}\InprocServer32";
item[i]	= NULL;
exp[i]	= "hh.dll";

i++;
name[i]	= "FastFind.org SubSearch";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/subsearch.asp";
key[i]	= "CLSID\{BD0BA5CD-7C8E-47ED-935E-1ABBAC9B29E0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "88313.dll";

i++;
name[i]	= "IETray";
url[i]	= "http://www.doxdesk.com/parasite/IETray.html";
key[i]	= "CLSID\{BD51AEC6-7991-4A60-94D6-D5FEBB655D10}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IEMsg.dll";

i++;
name[i]	= "AdRoar";
url[i]	= "http://doxdesk.com/parasite/AdRoar.html";
key[i]	= "CLSID\{BDF6CE3D-F5C5-4462-9814-3C8EAC330CA8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AdRoar.dll";

i++;
name[i] = "Hijacker, unidentified";
url[i]	= "";
key[i]	= "CLSID\{BEB133E5-FD72-43b7-8AFF-681831CC72D9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wiesasp2.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{BF755B85-EA69-4F58-9A59-D85F384A15FF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Unknown Adware";
url[i]	= "http://www.superadblocker.com/spywaredisplay.html?id=1281";
key[i]	= "CLSID\{C003C49F-53E4-4A72-B7D6-0B2B9997392F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "webdir.dll";

i++;
name[i]	= "Spyware.DigitalNames";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/spyware.digitalnames.html";
key[i]	= "CLSID\{C18517DA-CA70-46CE-86F4-882F6B62E975}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bms.dll";

i++;
name[i]	= "NavExcel browser helper";
url[i]	= "http://www.doxdesk.com/parasite/NavExcel.html";
key[i]	= "CLSID\{C1E58A84-95B3-4630-B8C2-D06B77B7A0FC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Nhelper.dll";

i++;
name[i]	= "Gigasearch.biz hijacker";
url[i]	= "";
key[i]	= "CLSID\{C1EA1782-8E6E-4ea4-9800-B68DE41F1A26}\InprocServer32";
item[i]	= NULL;
exp[i]	= "gigasoft.dll";

i++;
name[i]	= "iWon Toolbar";
url[i]	= "http://www.doxdesk.com/parasite/Aornum.html";
key[i]	= "CLSID\{C298fb42-e3e2-11d3-adcd-0050dac24e8f}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iwonbar.dll";

i++;
name[i]	= "Wishbone Toolbar";
url[i]	= "http://www.wishbonemedia.com/products.html";
key[i]	= "CLSID\{C331BD6E-06AB-41A0-B95F-D7CA379ACEAA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "WBM.DLL";

i++;
name[i]	= "Vividence Connector";
url[i]	= "http://www.vividence.com/public/products/vividence+xms+enterprise/vividence+xms+enterprise/connector.htm";
key[i]	= "CLSID\{C3BCC488-1AE7-11D4-AB82-0010A4EC2338}\InprocServer32";
item[i]	= NULL;
exp[i]	= "hoproxy.dll";

i++;
name[i]	= "Troj/Bamer-B";
url[i]	= "http://www.sophos.com/virusinfo/analyses/trojbamerb.html";
key[i]	= "CLSID\{C41A1C0E-EA6C-11D4-B1B8-444553540000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "rundll32.dll";

i++;
name[i] = "http://www.doxdesk.com/parasite/InetSpeak.html";
url[i]	= "eBoom Search Bar,  InetSpeak varian";
key[i]	= "CLSID\{C4D99500-4C77-11D4-93B7-0040950570BA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "boombar.dll";

i++;
name[i]	= "SideSearch variant";
url[i]	= "http://doxdesk.com/parasite/Sidesearch.html";
key[i]	= "CLSID\{C5183ABC-EB6E-4E05-B8C9-500A16B6CF94}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sep.dll";

i++;
name[i]	= "MyBHOSpy (suspected spyware)";
url[i]	= "";
key[i]	= "CLSID\{C52CBAEC-D969-4635-9F50-426CC15CE463}\InprocServer32";
item[i]	= NULL;
exp[i]	= "413";

i++;
name[i]	= "BlazeFind Websearch";
url[i]	= "http://www.spywareguide.com/product_show.php?id=724";
key[i]	= "CLSID\{C5941EE5-6DFA-11D8-86B0-0002441A9695}\InprocServer32";
item[i]	= NULL;
exp[i]	= "3_0_1browserhelper3.dll";

i++;
name[i]	= "Coulomb dialer related parasite";
url[i]	= "";
key[i]	= "CLSID\{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE50}\InprocServer32";
item[i]	= NULL;
exp[i]	= "saristar.dll";

i++;
name[i]	= "OnWebMedia adware variant";
url[i]	= "";
key[i]	= "CLSID\{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE51}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AdEnh.dll";

i++;
name[i]	= "IE Redirector.  browser hijacker";
url[i]	= "";
key[i]	= "CLSID\{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE53}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ieredir.dll";

i++;
name[i]	= "OnWebMedia adware variant";
url[i]	= "";
key[i]	= "CLSID\{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE56}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AdEnh.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{C69FA570-7FDE-4C49-A7BC-CB1CF24BE66B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "EasyBar/Toolbarcash";
url[i]	= "http://www.pestpatrol.com/pestinfo/t/toolbarcash_com.asp";
key[i]	= "CLSID\{C77E900A-FF55-400E-9BAA-E042C8212898}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ToolbarStarter.dll";

i++;
name[i]	= "System61 hijacker";
url[i]	= "";
key[i]	= "CLSID\{C7967580-5F17-11D4-AAC2-0000B4936E0C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "System61.dll";

i++;
name[i]	= "NetPal/PrizePopper";
url[i]	= "http://www.doxdesk.com/parasite/NetPal.html";
key[i]	= "CLSID\{C7ADE150-743D-11D4-8141-00E029626F6A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "KER7120.DLL";

i++;
name[i]	= "i-Lookup/Chgrgs";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{C82B55F0-60E0-478C-BC55-E4E22F11301D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Chgrgs.dll";

i++;
name[i]	= "Webhancer";
url[i]	= "http://www.cexx.org/webhancer.htm ";
key[i]	= "CLSID\{C900B400-CDFE-11D3-976A-00E02913A9E0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Whiehlpr.dll";

i++;
name[i]	= "SurfSideKick adware";
url[i]	= "http://www.spynet.com/spyware/spyware-SurfSideKick.aspx";
key[i]	= "CLSID\{CA0E28FA-1AFD-4C21-A8DC-70EB5BE2F076}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SskBho.dll";

i++;
name[i]	= "CnsMin variant";
url[i]	= "http://www.doxdesk.com/parasite/CnsMin.html";
key[i]	= "CLSID\{CA92B524-BC8A-4610-BD2C-6BD3E28155D0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bdhelper.dll";

i++;
name[i]	= "Adware.Begin2Search";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.begin2search.html";
key[i]	= "CLSID\{CB5B2BC6-F957-4D8A-BE67-83F3EC58BA01}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dsktrf.dll";

i++;
name[i]	= "I-Lookup";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{CBA523B2-1906-4D14-95A2-CD8E233701C7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "waeb.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{CBEFB350-ED5B-4115-B846-C1041676B377}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CustomIE.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{CBEFB350-ED5B-4115-B846-C1041676B388}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CustIE32.dll";

i++;
name[i]	= "esyndicate.com/seeq.com toolbar";
url[i]	= "";
key[i]	= "CLSID\{CC378B83-9577-44D0-B4F8-0DD965E176FC}\InprocServer32";
item[i]	= NULL;
exp[i]	= "esyn.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{CC916B4B-BE44-4026-A19D-8C74BBD23361}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Gstyle~1.dll";

i++;
name[i]	= "CSApp";
url[i]	= "http://www.pestpatrol.com/PestInfo/c/csapp_dll.asp#Detection%20and%20Removal";
key[i]	= "CLSID\{CD209A08-98B5-4669-AF9F-447AC5253356}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CSapp.dll";

i++;
name[i]	= "SearchCentrix adware variant";
url[i]	= "http://www.kephyr.com/spywarescanner/library/searchcentrix.barbho/index.phtml";
key[i]	= "CLSID\{CD2A865B-6C0F-44F9-BAA1-7CDB31E04BC8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BarBHO.dll";

i++;
name[i]	= "GoZilla";
url[i]	= "http://www.oit.duke.edu/ats/support/spyware/gozilla.html";
key[i]	= "CLSID\{CD4C3CF0-4B15-11D1-ABED-709549C10000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Goiehlp.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{CDBCFEAE-10BA-482C-9F6E-FC67207082D8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mdefshop.dll";

i++;
name[i]	= "eXact Advertising";
url[i]	= "http://www.doxdesk.com/parasite/BargainBuddy.html";
key[i]	= "CLSID\{CE188402-6EE7-4022-8868-AB25173A3E14}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mscb.dll";

i++;
name[i]	= "Bargain Buddy";
url[i]	= "http://www.doxdesk.com/parasite/BargainBuddy.html";
key[i]	= "CLSID\{CE31A1F7-3D90-4874-8FBE-A5D97F8BC8F1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Apuc.dll";

i++;
name[i]	= "URLBlaze";
url[i]	= "http://www.urlblaze.com";
key[i]	= "CLSID\{CE7C3CF0-4B15-11D1-ABED-709549C10000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ubmon.dll";

i++;
name[i]	= "ShopNavSearch/Srng";
url[i]	= "http://www.doxdesk.com/parasite/Srng.html";
key[i]	= "CLSID\{CE7C3CF0-4B15-11D1-ABED-709549C10000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Iehelper.dll";

i++;
name[i]	= "Win32.StartPage.np hijacker";
url[i]	= "";
key[i]	= "CLSID\{CE7C3CF0-4B15-11D1-ABED-709549C10000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "StopzillaBH0.dll";

i++;
name[i]	= "IeMonit";
url[i]	= "http://www.doxdesk.com/parasite/IEMonit.html";
key[i]	= "CLSID\{CE7C3CF0-4B15-11D1-ABED-709549C10001}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iemonit.dll";

i++;
name[i]	= "Trojan FAVADD.C";
url[i]	= "http://uk.trendmicro-europe.com/enterprise/security_info/ve_detail.php?Vname=TROJ_FAVADD.C";
key[i]	= "CLSID\{CE7C3CF0-4B15-11D1-ABED-709549C10020}\InprocServer32";
item[i]	= NULL;
exp[i]	= "random named";

i++;
name[i]	= "Ride MG adware";
url[i]	= "http://www.ridemg.com/about.html";
key[i]	= "CLSID\{CE7EF827-47CC-48EB-B570-C367F1E1277E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "x1ff.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-716D61788264}\InprocServer32";
item[i]	= NULL;
exp[i]	= "max8264.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-716D74632608}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mtc2608.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717177650486}\InprocServer32";
item[i]	= NULL;
exp[i]	= "QWE0486.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717177654820}\InprocServer32";
item[i]	= NULL;
exp[i]	= "qwe4820.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717177657972}\InprocServer32";
item[i]	= NULL;
exp[i]	= "qwe7972.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717177658264}\InprocServer32";
item[i]	= NULL;
exp[i]	= "max8264.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-7173706D1316}\InprocServer32";
item[i]	= NULL;
exp[i]	= "spm1316.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-7173706D4820}\InprocServer32";
item[i]	= NULL;
exp[i]	= "spm4820.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-71766C641306}\InprocServer32";
item[i]	= NULL;
exp[i]	= "vld1306.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717765721306}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wer1306.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717765721316}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wer1316.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717765724820}\InprocServer32";
item[i]	= NULL;
exp[i]	= "wer4820.dll";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717965725750}\InprocServer32";
item[i]	= NULL;
exp[i]	= "yer5750";

i++;
name[i]	= "Tubby/MakeMeSearch/Spyware.Arau parasite";
url[i]	= "http://www.doxdesk.com/parasite/Tubby.html";
key[i]	= "CLSID\{CF021F40-3E14-23A5-CBA2-717965726032}\InprocServer32";
item[i]	= NULL;
exp[i]	= "yer6032.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{D14641FA-445B-448E-9994-209f7AF15641}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mbho.dll";

i++;
name[i]	= "Comet Cursor";
url[i]	= "http://www.doxdesk.com/parasite/CometCursor.html";
key[i]	= "CLSID\{D14D6793-9B65-11D3-80B6-00500487BDBA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Csbho.dll";

i++;
name[i]	= "CnsMin";
url[i]	= "http://www.doxdesk.com/parasite/CnsMin.html";
key[i]	= "CLSID\{D157330A-9EF3-49F8-9A67-4141AC41ADD4}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CnsHook.dll";

i++;
name[i]	= "Alexa Toolbar";
url[i]	= "http://pages.alexa.com/prod_serv/webmasters.html?p=Dest_W_t_40_L1";
key[i]	= "CLSID\{D1F6ABEF-B889-11D2-8E3C-DCCA155F9A71}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Alexaie.dll";

i++;
name[i]	= "ClearStream Accelerator";
url[i]	= "http://www.spyany.com/program/article_spw_rm_ClearStream_Accelerator.html";
key[i]	= "CLSID\{D319662B-D5BF-4538-ADF3-8D3E36362608}\InprocServer32";
item[i]	= NULL;
exp[i]	= "x0ff.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{D34F08C5-4F18-477c-86CB-1A9BEECFE37B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "BrowserPal Toolbar";
url[i]	= "http://www.doxdesk.com/parasite/BrowserAid.html";
key[i]	= "CLSID\{D34F641F-5210-4EB0-8ED5-9179F47E15B7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "blckbho.dll";

i++;
name[i]	= "EZCybersearch/Surebar";
url[i]	= "http://www.doxdesk.com/parasite/ezCyberSearch.html";
key[i]	= "CLSID\{D3F01312-8A3D-4D41-A4FA-FB61D295CB6B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Surebar.dll";

i++;
name[i]	= "Lop.com";
url[i]	= "http://www.doxdesk.com/parasite/lop.html";
key[i]	= "CLSID\{D44B5436-B3E4-4595-B0E9-106690E70A58}\InprocServer32";
item[i]	= NULL;
exp[i]	= "plg_ie0.dll";

i++;
name[i]	= "Xupiter Orbitexplorer";
url[i]	= "http://www.doxdesk.com/parasite/Xupiter.html";
key[i]	= "CLSID\{D48F2E28-68E2-4920-9848-D6E6C7AB3EB7}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Redirector.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{D4D505DF-D582-400c-91B6-84921012AFE3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "pdf";
#upd.dll / PDF****.dll";

i++;
name[i]	= "Adware.Margoc";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.margoc.html";
key[i]	= "CLSID\{D537A3D0-8C07-4D62-953F-162207F5090D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "regsvrac32.dll";

i++;
name[i]	= "Whazit";
url[i]	= "http://www.doxdesk.com/parasite/Whazit.html";
key[i]	= "CLSID\{D5B72AED-E54A-11D6-B1B2-444553540000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bho.dll";

i++;
name[i]	= "SmartPops";
url[i]	= "http://www.kephyr.com/spywarescanner/library/smartpops/index.phtml";
key[i]	= "CLSID\{D5C778F1-CF13-4E70-ADF0-45A953E7CB8B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ne.dll";

i++;
name[i]	= "power-linking-profits.com toolbar";
url[i]	= "";
key[i]	= "CLSID\{D6223CBC-A263-4CB1-B35E-1AE40FEF3B3B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ietoolbar.dll";

i++;
name[i]	= "InetSpeak";
url[i]	= "http://www.doxdesk.com/parasite/InetSpeak.html";
key[i]	= "CLSID\{D6862A22-1DD6-11D3-BB7C-444553540000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bho.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{D6964FD8-3AF1-4A2A-ABB7-3D0C62924FD6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "HuntBar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{D6DFF6D8-B94B-4720-B730-1C38C7065C3B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Btlink.dll";

i++;
name[i]	= "HuntBar";
url[i]	= "http://www.doxdesk.com/parasite/HuntBar.html";
key[i]	= "CLSID\{D6E66235-7AA6-44ED-A06C-6F2033B1D993}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msiein.dll";

i++;
name[i]	= "Qcbar/AdultLinks";
url[i]	= "http://www.doxdesk.com/parasite/AdultLinks.html";
key[i]	= "CLSID\{D6FC35D1-04AB-4D40-94CF-2E5AE4D0F8D2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "llch.dll";

i++;
name[i]	= "SideStep";
url[i]	= "http://www.doxdesk.com/parasite/SideStep.html";
key[i]	= "CLSID\{D714A94F-123A-45CC-8F03-040BCAF82AD6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SbCIe028.dll";

i++;
name[i]	= "0CAT YellowPages";
url[i]	= "http://www.spynet.com/spyware/spyware-0cat-yellowpages.aspx";
key[i]	= "CLSID\{D797AD6C-6447-4DB4-91D0-090344408E72}\InprocServer32";
item[i]	= NULL;
exp[i]	= "STIEbar.dll";

i++;
name[i]	= "Trojan.Magise";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.magise.html";
key[i]	= "CLSID\{D7BF3304-138B-4DD5-86EE-491BB6A2286C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msearch.dll";

i++;
name[i]	= "Whazit";
url[i]	= "http://www.doxdesk.com/parasite/Whazit.html";
key[i]	= "CLSID\{D7D7004C-A763-4F8C-B0D4-55A7E017E69D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "newones.dll";

i++;
name[i]	= "NavExcel";
url[i]	= "http://www.doxdesk.com/parasite/NavExcel.html";
key[i]	= "CLSID\{D80C4E21-C346-4E21-8E64-20746AA20AEB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "NavExcelBar.dll";

i++;
name[i]	= "Comodo Trust Toolbar";
url[i]	= "http://www.trusttoolbar.com/";
key[i]	= "CLSID\{D80E1356-AC78-4218-961C-A7689B4CB7FE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ttbbho.dll";

i++;
name[i]	= "Adware.DealHelper";
url[i]	= "http://sarc.com/avcenter/venc/data/pf/adware.dealhelper.html";
key[i]	= "CLSID\{D848A3CA-0BFB-4DE0-BA9E-A57F0CCA1C13}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Dealhlpr.dll";

i++;
name[i]	= "TROJ_DELF.CR trojan";
url[i]	= "http://uk.trendmicro-europe.com/enterprise/security_info/ve_detail.php?VName=TROJ_DELF.CR";
key[i]	= "CLSID\{D8569837-3CD6-4AD7-9A77-65975B581925}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Unidentified hijacker";
url[i]	= "";
key[i]	= "CLSID\{D879A0F1-2B3B-4409-8879-FAD6E49E1EA9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mshtmpre.dll";

i++;
name[i]	= "MediaUpdate/SafeSurfing";
url[i]	= "http://www.doxdesk.com/parasite/MediaUpdate.html";
key[i]	= "CLSID\{D8E25C53-9508-4f5c-9249-D98D438891D5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ssurf022.dll";

i++;
name[i]	= "Adware.IEPageHelper";
url[i]	= "http://www.pestpatrol.com/pestinfo/a/adware_iepagehelper.asp";
key[i]	= "CLSID\{D8E25C53-9508-4f5c-9249-D98D438891D5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "inetdctr.dll";

i++;
name[i]	= "Csearch";
url[i]	= "http://www.pestpatrol.com/pestinfo/c/csearch.asp";
key[i]	= "CLSID\{D8FA0364-7866-40A7-B340-A6069265AD9F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Csearch.dll";

i++;
name[i]	= "Unidentified malware";
url[i]	= "";
key[i]	= "CLSID\{D8FF9A84-FEB9-4B4B-B36B-D46570203C39}\InprocServer32";
item[i]	= NULL;
exp[i]	= "key.dll";

i++;
name[i]	= "FastFind.org SubSearch";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/subsearch.asp";
key[i]	= "CLSID\{D97287B6-4018-4060-948D-54D2122FC5C3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "0002C00.dll";

i++;
name[i]	= "SecondPower Multimedia Speedbar";
url[i]	= "http://support.microsoft.com/default.aspx?kbid=320159";
key[i]	= "CLSID\{D985E70B-97F1-477E-AF6C-66E496DEDBD6}\InprocServer32";
item[i]	= NULL;
exp[i]	= "2ndpower.dll";

i++;
name[i]	= "Subsearch";
url[i]	= "http://www.doxdesk.com/parasite/SubSearch.html";
key[i]	= "CLSID\{D9A5A49C-60EB-4C07-8570-8FB8FE825E7C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sbsrch_v2.dll";

i++;
name[i]	= "EZSearching";
url[i]	= "http://www.doxdesk.com/parasite/ezSearching.html";
key[i]	= "CLSID\{DB0018A2-F7D9-4B71-9651-640143DF23F9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ctap";


#koma
i++;
name[i] = "Keylogger, probably LoveTester related";
url[i]	= "http://spamwatch.codefish.net.au/modules.php?op=modload&name=News&file=index&catid=&topic=24";
key[i]	= "CLSID\{DCE80CA4-B555-44D8-B423-A75D6C345EE1}\InprocServer32";
item[i]	= NULL;
exp[i]	= "stype10.dll";

i++;
name[i]	= "MacigControl";
url[i]	= "http://www.doxdesk.com/parasite/MagicControl.html";
key[i]	= "CLSID\{DE614603-6320-4046-A7A7-6A69CEC26F14}\InprocServer32";
item[i]	= NULL;
exp[i]	= "4b_1,0,0,5_navpmc.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{DF57FEB6-9BCE-45E3-AA65-BE327B8CCE7F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Divago Surfairy";
url[i]	= "http://www.doxdesk.com/parasite/Surfairy.html";
key[i]	= "CLSID\{E0B9B5FE-B66E-4FB0-A1D9-726F0E743CFD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SurfairyPP.dll";

i++;
name[i]	= "AdRoar";
url[i]	= "http://doxdesk.com/parasite/AdRoar.html";
key[i]	= "CLSID\{E0F0E0E1-5D45-11D4-BC00-2DCC73302D70}\InprocServer32";
item[i]	= NULL;
exp[i]	= "cpr.dll";

i++;
name[i]	= "Unidentified adware";
url[i]	= "";
key[i]	= "CLSID\{E155EDD6-FA1E-4876-8FB2-5FB358014EBE}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sequitur1b.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{E2DDF680-9905-4dee-8C64-0A5DE7FE133C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mssearch.dll";

i++;
name[i]	= "Trojan.Win32.Delf.cf";
url[i]	= "";
key[i]	= "CLSID\{E412F14A-E998-4543-9E7A-1031A3189A87}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "i-Lookup/GlobalWebSearch";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{E539DEA3-BA67-4F1F-A897-5F2F4F29A063}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winenc32.dll";

i++;
name[i]	= "CnsMin related";
url[i]	= "http://www.doxdesk.com/parasite/CnsMin.html";
key[i]	= "CLSID\{E5E4E352-6947-44EE-A420-DB84EFD3FE93}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ehelper.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{E7AFFF2A-1B57-49C7-BF6B-E5123394C970}\InprocServer32";
item[i]	= NULL;
exp[i]	= "webinfo.dll";

i++;
name[i]	= "Best Phrases adware";
url[i]	= "http://www.spyany.com/program/article_adw_rm_Best_Phrases.html";
key[i]	= "CLSID\{E8B4F3AA-9509-4081-9A85-914D5E9BEC81}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bpv1a.dll";

i++;
name[i]	= "MidAddle adware";
url[i]	= "http://www.adrants.com/2004/06/adspyre-launches-midaddle-ad-system.php";
key[i]	= "CLSID\{E8EAEB34-F7B5-4C55-87FF-720FAF53D841}\InprocServer32";
item[i]	= NULL;
exp[i]	= "midaddle.dll";

i++;
name[i]	= "AdBlaster Adware";
url[i]	= "http://www.spyany.com/program/article_adw_rm_AdBlaster.html";
key[i]	= "CLSID\{E9147A0A-A866-4214-B47C-DA821891240F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ngsw31.dll";

i++;
name[i]	= "NewtonKnows toolbar variant";
url[i]	= "http://www.doxdesk.com/parasite/NewtonKnows.html";
key[i]	= "CLSID\{E9407738-A996-421A-A309-5C93C699E10A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ntoolbar.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{E9C1FD9A-46B0-4185-84ED-E2F8ACD4A262}\InprocServer32";
item[i]	= NULL;
exp[i]	= "kdp";

i++;
name[i]	= "Gigasearch hijacker";
url[i]	= "";
key[i]	= "CLSID\{EADD3112-0CF8-444b-AC0F-EBA38E004554}\InprocServer32";
item[i]	= NULL;
exp[i]	= "giga32.dll";

#koma

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{EB23F789-F17F-4bcc-988B-6B70A3A67E9C}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Zero-Popup.dll";

i++;
name[i] = "SpiderSearch, iLookup parasite variant";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{EB386233-65D7-46DC-A73D-0E02F2F844A9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "winsps32.dll";

i++;
name[i]	= "FavoriteMan/SpyAssault";
url[i]	= "http://www.doxdesk.com/parasite/FavoriteMan.html";
key[i]	= "CLSID\{EBBD88E5-C372-469D-B4C5-1FE00352AB9B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "ss32.dll";

i++;
name[i]	= "Aureate/Radiate";
url[i]	= "http://www.cexx.org/aureate.htm";
key[i]	= "CLSID\{EBBFE27C-BDF0-11D2-BBE5-00609419F467}\InprocServer32";
item[i]	= NULL;
exp[i]	= "amcis.dll";

i++;
name[i]	= "i-search.us hijacker";
url[i]	= "";
key[i]	= "CLSID\{ECAD9C14-ED46-D58A-E847-ADBEFC8D37EB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "IBHO2.DLL";

i++;
name[i]	= "SearchMiracle.EliteBar";
url[i]	= "http://www.spynet.com/spyware/spyware-SearchMiracle.EliteBar.aspx";
key[i]	= "CLSID\{ED103D9F-3070-4580-AB1E-E5C179C1AE41}\InprocServer32";
item[i]	= NULL;
exp[i]	= "EliteSideBar";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{ED5ABC42-8E4F-4C39-9972-F0CF619D672F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "Icoo Loader";
url[i]	= "http://www.by-users.co.uk/forums/?board=help&action=display&num=1085918311";
key[i]	= "CLSID\{ED657BAF-1EE5-4A07-9D2E-6D0525EFC69B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "icoourlext.dll";

i++;
name[i]	= "UCmore toolbar";
url[i]	= "http://www.doxdesk.com/parasite/UCmore.html";
key[i]	= "CLSID\{ED8DB0FD-D8F4-4b2c-BB5B-9EF040FE104D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Ucmie.dll";

i++;
name[i]	= "NewtonKnows search bar";
url[i]	= "http://www.doxdesk.com/parasite/NewtonKnows.html";
key[i]	= "CLSID\{EE392A64-F30B-47C8-A363-CDA1CEC7DC1B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Bar.dll";

i++;
name[i]	= "RelatedLinks adware";
url[i]	= "http://www.kephyr.com/spywarescanner/library/relatedlinks.lbbho/index.phtml";
key[i]	= "CLSID\{EFD84954-6B46-42f4-81F3-94CE9A77052D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "lbbho.dll";

i++;
name[i] = "Parasite, as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{EFF80427-F837-4B74-8834-BAF18E0553FD}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "Adware.Begin2Search";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.begin2search.html";
key[i]	= "CLSID\{F0C08B30-BA30-4FEB-924B-2E250CF0697D}\InprocServer32";
item[i]	= NULL;
exp[i]	= "siq.dll";

i++;
name[i]	= "ZyncosMark";
url[i]	= "http://www.tek-tips.com/gviewthread.cfm/lev2/8/lev3/57/pid/538/qid/221627";
key[i]	= "CLSID\{F0DC0CFE-D11A-489B-84C0-63748AFAABF3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Cmctl.dll";

i++;
name[i]	= "Keywords";
url[i]	= "http://doxdesk.com/parasite/Keywords.html parasite";
key[i]	= "CLSID\{F104576A-91BA-40AD-91DE-2C20801339AB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Keywords001.dll";

i++;
name[i]	= "Adware.Syslibie";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.syslibie.html";
key[i]	= "CLSID\{F195A1A9-4033-4E5B-B85C-848C3E31A83A}\InprocServer32";
item[i]	= NULL;
exp[i]	= "syslibie.dll";

i++;
name[i]	= "Alexa";
url[i]	= "http://www.safersite.com/PestInfo/a/Alexa_Toolbar.asp";
key[i]	= "CLSID\{F1FABE79-25FC-46de-8C5A-2C6DB9D64333}\InprocServer32";
item[i]	= NULL;
exp[i]	= "AlxTB1.dll";

i++;
name[i]	= "SafeguardProtect/Veevo";
url[i]	= "http://www.pestpatrol.com/PestInfo/s/safeguardprotect.asp";
key[i]	= "CLSID\{F281FFC7-6C63-4bf9-83F2-AB7A6157B109}\InprocServer32";
item[i]	= NULL;
exp[i]	= "kdpupd.dll";

i++;
name[i]	= "Roings.com adware";
url[i]	= "http://www.pestpatrol.com/PestInfo/r/roings_com.asp";
key[i]	= "CLSID\{F2863EDE-7980-443A-AEA2-0F46076D590F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Wat.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{F325E940-45EE-11D7-A420-444553540000}\InprocServer32";
item[i]	= NULL;
exp[i]	= "M030206POHS.DLL";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{F32F8ECD-6CF3-459D-82F2-9738392C85A8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "GamSYS";
url[i]	= "http://doxdesk.com/parasite/GAMsys.html";
key[i]	= "CLSID\{F36C1198-FC6B-4012-9928-DFA76FB56CC3}\InprocServer32";
item[i]	= NULL;
exp[i]	= "GAMhelper.dll";

i++;
name[i]	= "BestPhrases variant";
url[i]	= "http://www.pestpatrol.com/PestInfo/b/bpv1a_dll.asp";
key[i]	= "CLSID\{F4A645D0-D4D5-439E-9DBC-B31BBD9CB890}\InprocServer32";
item[i]	= NULL;
exp[i]	= "BPV2s.dll";

i++;
name[i]	= "eXact Advertising";
url[i]	= "http://www.doxdesk.com/parasite/BargainBuddy.html";
key[i]	= "CLSID\{F4E04583-354E-4076-BE7D-ED6A80FD66DA}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msbe.dll";

i++;
name[i]	= "Netguarder Web Cleaner";
url[i]	= "http://210.82.112.58/en/index.htm";
key[i]	= "CLSID\{F585D290-1BF4-480A-AEC2-4182593F1E32}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Webtool.dll";

i++;
name[i]	= "WurldMedia";
url[i]	= "http://www.doxdesk.com/parasite/WurldMedia.html";
key[i]	= "CLSID\{F59D88CF-939A-4E50-9587-65A2E22EF077}\InprocServer32";
item[i]	= NULL;
exp[i]	= "mob030612.dll";

i++;
name[i]	= "Adware.Magicads";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.magicads.html";
key[i]	= "CLSID\{F760CB9E-C60F-4A89-890E-FAE8B849493E}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Madise.dll";

i++;
name[i]	= "Dyfuca/Internet Optimizer";
url[i]	= "http://www.doxdesk.com/parasite/InternetOptimizer.html";
key[i]	= "CLSID\{F7F808F0-6F7D-442C-93E3-4A4827C2E4C8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "opti130.dll";

i++;
name[i]	= "eXact Search Bar";
url[i]	= "http://www.doxdesk.com/parasite/eXactSearch.html";
key[i]	= "CLSID\{F9765480-72D1-11D4-A75A-004F49045A87}\InprocServer32";
item[i]	= NULL;
exp[i]	= "eXactToolbar.dll";

i++;
name[i]	= "Adware.Margoc variant";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.margoc.html";
key[i]	= "CLSID\{FA040B34-FBE9-4BEF-9D85-F90BECAACA99}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dll";

i++;
name[i]	= "EliteBar/SearchMiracle adware";
url[i]	= "http://www.giantcompany.com/antispyware/research/spyware/spyware-SearchMiracle.EliteBar.aspx";
key[i]	= "CLSID\{FA6548E9-78F5-4025-9D7B-FC1367789C38}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Elitebar.dll";

i++;
name[i]	= "Meridian popupper";
url[i]	= "http://www.doxdesk.com/parasite/Meridian.html";
key[i]	= "CLSID\{FA79FA22-8DB3-43D1-997B-6DBFD8845569}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Myaccess.dll";

i++;
name[i]	= "AdRoar";
url[i]	= "http://doxdesk.com/parasite/AdRoar.html";
key[i]	= "CLSID\{FAC6E0E1-5D45-4907-BC00-302D702DCC73}\InprocServer32";
item[i]	= NULL;
exp[i]	= "cpr.dll";

i++;
name[i]	= "i-lookup search bar";
url[i]	= "http://www.doxdesk.com/parasite/ILookup.html";
key[i]	= "CLSID\{FBAA0B9E-A059-43E4-9699-76EB0AEB975B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Gws.dll";

i++;
name[i]	= "BlazeFind Websearch";
url[i]	= "http://www.spywareguide.com/product_show.php?id=724";
key[i]	= "CLSID\{FBED6A02-71FB-11D8-86B0-0002441A9695}\InprocServer32";
item[i]	= NULL;
exp[i]	= "5_0_1browserhelper5.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{FC2593E3-3E5A-410F-AF3D-82613CCE58E5}\InprocServer32";
item[i]	= NULL;
exp[i]	= "sr.dll";

i++;
name[i] = "Hijacker,  as yet unidentified";
url[i]	= "";
key[i]	= "CLSID\{FC4C5EAE-66EE-11D4-BC67-0000E8E582D2}\InprocServer32";
item[i]	= NULL;
exp[i]	= "e2bho.dll";

i++;
name[i]	= "Xpehbam.biz dialer related malware";
url[i]	= "";
key[i]	= "CLSID\{FCADDC14-BD46-408A-9842-111111111111}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Backup.dll";

i++;
name[i]	= "Xpehbam.biz dialer related malware";
url[i]	= "";
key[i]	= "CLSID\{FCADDC14-BD46-408A-9842-CDB57890086B}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Dial.dll";

i++;
name[i]	= "ClientMan";
url[i]	= "http://www.doxdesk.com/parasite/ClientMan.html";
key[i]	= "CLSID\{FCADDC14-BD46-408A-9842-CDBE1C6D37EB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "browserhelpere";

i++;
name[i]	= "AdwareSpy";
url[i]	= "http://www.netrn.net/archives2/000596.html";
key[i]	= "CLSID\{FCADDC14-BD46-408A-9842-CDBE1C6D37EB}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Adwarespy.dll";

i++;
name[i]	= "Adware.MultiClicker";
url[i]	= "";
key[i]	= "CLSID\{FD3A6AB4-5527-4B52-90AF-F90CD3270861}\InprocServer32";
item[i]	= NULL;
exp[i]	= "inetconnect.dll";

i++;
name[i]	= "VirtuMonde adware variant";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html";
key[i]	= "CLSID\{FD8609EC-7D7C-4778-AB8F-0053245550EF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "dat";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{FD9BC004-8331-4457-B830-4759FF704C22}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Msiesh.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
key[i]	= "CLSID\{FF1BF4C7-4E08-4A28-A43F-9D60A9F7A880}\InprocServer32";
item[i]	= NULL;
exp[i]	= "Mshelper.dll";

i++;
name[i]	= "StickyPops.com adware";
url[i]	= "";
key[i]	= "CLSID\{FF4E2C50-BCF3-47cf-952A-A512F5B5D0E8}\InprocServer32";
item[i]	= NULL;
exp[i]	= "DNSProxy.dll";

i++;
name[i]	= "Trojan.Magise";
url[i]	= "http://securityresponse.symantec.com/avcenter/venc/data/trojan.magise.html";
key[i]	= "CLSID\{FFF5092F-7172-4018-827B-FA5868FB0478}\InprocServer32";
item[i]	= NULL;
exp[i]	= "msearch.dll";

i++;
name[i]	= "CasinoRewards software";
url[i]	= "";
key[i]	= "CLSID\{FF905E0C-CFE9-4A90-AFFF-C13AF5D908F0}\InprocServer32";
item[i]	= NULL;
exp[i]	= "CasinoRewardsExplorerToolbar.dll";

i++;
name[i]	= "VX2 Variant";
url[i]	= "http://www.doxdesk.com/parasite/Transponder.html ";
key[i]	= "CLSID\{FFD2825E-0785-40C5-9A41-518F53A8261F}\InprocServer32";
item[i]	= NULL;
exp[i]	= "SiteHlpr.dll";

i++;
name[i]	= "MPGcom toolbar";
url[i]	= "http://www.xblock.com/product_show.php?id=726";
key[i]	= "CLSID\{FFFFFFFF-FFFF-FFFF-FFFF-5F8507C5F4E9}\InprocServer32";
item[i]	= NULL;
exp[i]	= "iempg.dll";

i++;
name[i]	= "EasySearch/UmaxSearch";
url[i]	= "http://sarc.com/avcenter/venc/data/adware.umaxsearch.html";
key[i]	= "CLSID\{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}\InprocServer32";
item[i]	= NULL;
exp[i]	= "bin376.dll";

##################################################

if (DEBUG) display("start main for detection from registry\n");
for(i=0;name[i];i++)
{
 if (DEBUG) display("clsid ",i,": ",name[i],"\n");
  check_reg(name:name[i], url:url[i], key:key[i], item:item[i], exp:exp[i]);
}
if (DEBUG) display("end main for detection from registry\n");

##################################################
# Random Class ID
##################################################

i=0;
name = make_list();
url  = make_list();
exp  = make_list();


name[i]	= "NetNucleus/Mirar webband";
url[i]	= "http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb42/index.phtml";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "WinNB42.dll";

i++;
name[i]	= "NetNucleus/Mirar webband";
url[i]	= "http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb41/index.phtml";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "WinNB41.dll";

i++;
name[i]	= "Trojan.Win32.StartPage.ky hijacker";
url[i]	= "";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "msie32.dll";

i++;
name[i]	= "RelatedLinks adware";
url[i]	= "http://www.kephyr.com/spywarescanner/library/relatedlinks.lbbho/index.phtml";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "lbbho.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "madopew.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "mfplay.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "msdoh.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "rpcnt4.dll";

i++;
name[i]	= "hijacker";
url[i]	= "http://computercops.biz/startuplist-6098.html";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "msadblock32.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
exp[i]	= "localsplnet.dll";

i++;
name[i]	= "CoolWebSearch parasite variant";
url[i]	= "http://www.richardthelionhearted.com/~merijn/cwschronicles.html#";
#key[i]	= "CLSID\{********-****-****-****-************}\InprocServer32";
#item[i]	= NULL;
#exp[i]	= "Snnpapi.dll";
exp[i]	= "aclui.dll";

i++;
name[i] = NULL;

##################################################


RegCloseKey(handle:handle);


rootfile = hotfix_get_systemroot();
if ( ! rootfile ) exit(0);

NetUseDel(close:FALSE);
share =  ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:rootfile); 
r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}


if (DEBUG) display("start main for detection from hardrive\n");
for(i=0;name[i];i++)
{
   if (DEBUG) display("file ",i,": ",name[i],"\n");
   
   file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1\" + exp[i], string:rootfile); 
   handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                        share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
   if( ! isnull(handle) )
   {
     report = string(
    "The dll '"+name[i]+"' is present on the remote host\n",
    "Solution : "+url[i]+"\n",
    "Risk factor : High"); 
    security_hole(port:port, data:report);
    CloseFile(handle:handle);
  }
}
if (DEBUG) display("end main for detection from hardrive\n");

NetUseDel();
