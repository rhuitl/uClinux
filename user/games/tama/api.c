/* includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "tama.h"

/* reads birth time from the tamagotchi file */
/* returns -1 on error */
int getbirth(char *name)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, tmp=0;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;
	
	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf)
			break;

	fclose(ptr);
	for(ctr=0; ctr<BUFLEN; ctr++) {
		if(buf[ctr]==':') tmp++;
		if(tmp==2) break;
	}

	return(atoi(buf+ctr+1));	
}

/* returns -1 on error*/
int getpassw(char *name, char *string)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, at;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf)
			break;

	fclose(ptr);
	for(ctr=0; ctr<BUFLEN; ctr++)
		if(buf[ctr]==':') break;
	at=ctr+1;
	for(ctr++; ctr<BUFLEN; ctr++)
		if(buf[ctr]==':') {
			buf[ctr]='\0';
			break;
		}

	strncpy(string, buf+at, MAXNAME);
	return 0;
}

/* reads last feeding time from the tamagotchi file */
/* returns -1 on error */
int gettime(char *name)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, tmp=0;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;
	
	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf)
			break;

	fclose(ptr);
	for(ctr=0; ctr<BUFLEN; ctr++) {
		if(buf[ctr]==':') tmp++;
		if(tmp==3) break;
	}

	return(atoi(buf+ctr+1));	
}

/* reads last petting time from the tamagotchi file */
/* returns -1 on error */
int getpet(char *name)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, tmp=0;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;
	
	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf)
			break;

	fclose(ptr);
	for(ctr=0; ctr<BUFLEN; ctr++) {
		if(buf[ctr]==':') tmp++;
		if(tmp==4) break;
	}

	return(atoi(buf+ctr+1));	
}

/* reads weight from the tamagotchi file */
/* returns INITWEIGHT on error */
int getweight(char *name)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, tmp=0;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return INITWEIGHT;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf)
			break;

	fclose(ptr);
	for(ctr=0; ctr<BUFLEN; ctr++) {
		if(buf[ctr]==':') tmp++;
		if(tmp==5) break;
	}

	return(atoi(buf+ctr+1));	
}

/* Change the weight of a Tamagotchi */
/* returns -1 on error */
int setweight(char *name, int weight)
{
	FILE *ptr, *tmp;
	char buf[BUFLEN], tama[MAXNAME+1], temp[MAXNAME];
	int ctr;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	if((tmp=tmpfile())==NULL)
		return -1;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		if(strstr(buf, tama)==buf) {
			if(getpassw(name, temp)<0) return -1;
			fprintf(tmp, "%s%s:%d:%d:%d:%d:\n", tama, temp,
				getbirth(name), gettime(name), getpet(name), weight);
			continue;
		}
		fputs(buf, tmp);
	}

	freopen(TAMAFILE, "w", ptr);
	rewind(tmp);

	while((ctr=getc(tmp))!=EOF)
		putc(ctr, ptr);

	fclose(ptr);
	fclose(tmp);
	return 0;
}

/* does a tamagotchi exist? returns 0 if so, -1 if not */
int exist(char *name)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;
	
	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf) {
			fclose(ptr);
			return 0;
		}
	fclose(ptr);
	return -1;
}

/* Check if string is a valid username or password */
int check(char *string)
{
	int ctr;

	if(strlen(string)>16)
		return -1;
	if(strstr(string, ":")!=NULL)
		return -1;

	for(ctr=0; ctr<strlen(string); ctr++)
		if(string[ctr]<48 || string[ctr]>126)
			return -1;

	return 0;
}

/* create new Tamagotchi profile */
int new(char *name, char *pass)
{
	FILE *ptr;
	int cur;

	if((ptr=fopen(TAMAFILE, "a"))==NULL)
		return -1;

	cur=time(NULL);
	fprintf(ptr, "%s:%s:%d:%d:%d:%d:\n", name, pass, cur, cur, cur, INITWEIGHT);
	fclose(ptr);
	return 0;
}
/* returns -1 if wrong, 0 if correct */
int checkpass(char *name, char *pass)
{
	FILE *ptr;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, at;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL)
		if(strstr(buf, tama)==buf)
			break;

	fclose(ptr);
	for(ctr=0; ctr<BUFLEN; ctr++)
		if(buf[ctr]==':') break;
	at=ctr+1;
	for(ctr++; ctr<BUFLEN; ctr++)
		if(buf[ctr]==':') {
			buf[ctr]='\0';
			break;
		}
	if(strcmp(pass, buf+at)==0)
		return 0;
	else return -1;
}

/* remove Tamagotchi profile */
void del(char *name)
{
	FILE *ptr, *tmp;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return;

	if((tmp=tmpfile())==NULL)
		return;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		if(strstr(buf, tama)==buf) continue;
		fputs(buf, tmp);
	}

	freopen(TAMAFILE, "w", ptr);
	rewind(tmp);

	while((ctr=getc(tmp))!=EOF)
		putc(ctr, ptr);

	fclose(ptr);
	fclose(tmp);
	return;
}

/* Change the password of an existing Tamagotchi */
int setpass(char *name, char *pass)
{
	FILE *ptr, *tmp;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	if((tmp=tmpfile())==NULL)
		return -1;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		if(strstr(buf, tama)==buf) {
			fprintf(tmp, "%s%s:%d:%d:%d:%d:\n", tama, pass, getbirth(name),
				gettime(name), getpet(name), getweight(name));
			continue;
		}
		fputs(buf, tmp);
	}

	freopen(TAMAFILE, "w", ptr);
	rewind(tmp);

	while((ctr=getc(tmp))!=EOF)
		putc(ctr, ptr);

	fclose(ptr);
	fclose(tmp);
	return 0;
}

/* Change the name of an existing Tamagotchi */
int setname(char *oldname, char *newname)
{
	FILE *ptr, *tmp;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	if((tmp=tmpfile())==NULL)
		return -1;

	strncpy(tama, oldname, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		if(strstr(buf, tama)==buf) {
			getpassw(oldname, buf);
			fprintf(tmp, "%s:%s:%d:%d:%d:%d:\n", newname, buf, getbirth(oldname),
				gettime(oldname), getpet(oldname), getweight(oldname));
			continue;
		}
		fputs(buf, tmp);
	}

	freopen(TAMAFILE, "w", ptr);
	rewind(tmp);

	while((ctr=getc(tmp))!=EOF)
		putc(ctr, ptr);

	fclose(ptr);
	fclose(tmp);
	return 0;
}

/* feed Tamagotchi */
/* returns -1 on error, 0 on success, 1 on not hungry */
int feed(char *name)
{
	FILE *ptr, *tmp;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, num=0;

	if((time(NULL)-gettime(name))/3600 < FEEDLIMIT)
		return 1;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	if((tmp=tmpfile())==NULL)
		return -1;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		if(strstr(buf, tama)==buf) {
			for(ctr=0; ctr<BUFLEN; ctr++) {
				if(buf[ctr]==':') num++;
				if(num==3) break;
			}
			buf[ctr+1]='\0';
			fprintf(tmp, "%s%d:%d:%d:\n", buf, (int)time(NULL),
				getpet(name), getweight(name)+1);
			continue;
		}
		fputs(buf, tmp);
	}

	freopen(TAMAFILE, "w", ptr);
	rewind(tmp);

	while((ctr=getc(tmp))!=EOF)
		putc(ctr, ptr);

	fclose(ptr);
	fclose(tmp);
	return 0;
}

/* pet Tamagotchi */
int pet(char *name)
{
	FILE *ptr, *tmp;
	char buf[BUFLEN], tama[MAXNAME+1];
	int ctr, num=0;

	if((ptr=fopen(TAMAFILE, "r"))==NULL)
		return -1;

	if((tmp=tmpfile())==NULL)
		return -1;

	strncpy(tama, name, MAXNAME);
	strcat(tama, ":");
	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		if(strstr(buf, tama)==buf) {
			for(ctr=0; ctr<BUFLEN; ctr++) {
				if(buf[ctr]==':') num++;
				if(num==4) break;
			}
			buf[ctr+1]='\0';
			fprintf(tmp, "%s%d:%d:\n", buf, (int)time(NULL),
				getweight(name));
			continue;
		}
		fputs(buf, tmp);
	}

	freopen(TAMAFILE, "w", ptr);
	rewind(tmp);

	while((ctr=getc(tmp))!=EOF)
		putc(ctr, ptr);

	fclose(ptr);
	fclose(tmp);
	return 0;
}
