#ifndef		_IFACEVARS_H_
#define		_IFACEVARS_H_

CVoidType	ifaceInit (void);

/*2.1*/
#define IFNUMBER	1

/*2.2*/
#define IFTABLE		1

/*2.2.1*/
#define	IFENTRY		1


/*2.2.1.**/
#define IFINDEX		1
#define IFDESCR		2
#define IFTYPE		3
#define IFMTU		4
#define IFSPEED		5
#define IFPHYSADDRESS	6
#define IFADMINSTATUS	7
#define IFOPERSTATUS	8
#define IFLASTCHANGE	9
#define IFINOCTETS	10
#define IFINUCASTPKTS	11
#define IFINNUCASTPKTS	12
#define IFINDISCARDS	13
#define IFINERRORS	14
#define IFINUNKNOWNPROTOS 15
#define IFOUTOCTETS	16
#define IFOUTUCASTPKTS	17
#define IFOUTNUCASTPKTS 18
#define IFOUTDISCARDS	19
#define IFOUTERRORS	20
#define IFOUTQLEN	21
#define IFSPECIFIC	22

#endif		/*	_IFACEVARS_H_	*/
