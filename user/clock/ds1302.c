/*********************************************************************
	DS1302.C		Pat Adamo, ADEMCO
	05/26/99

	This file handles the Dallas DS1302 Real Time Clock.

	On the Motorola Coldfire MCF5206, the DS1302 requires three port
	pins, designated as follows...
		RESET*  Port PP0
		CLOCK   Port PP1
		DATA    Port PP2
**********************************************************************/
#include "ds1302.h"
//MBAR must have been set to this by someone else
//This must match the setting done by the hardware set-up
#define MCF_MBAR	0x10000000

//Additional Sim registers
#define MCFPP_PPDDR	0x1c5	//Port A Data Direction Register (byte, r/w)
#define MCFPP_PPDAT	0x1c9	//Port A Data Register (byte, r/w)
#define MCFSIM_PAR	0xcb	//Pin Assignment reg (r/w)

//write
//#define DS1302(ds1302_bit,logical_value) \
//	{ \
//	if (!logical_value)         \
//		*((volatile unsigned char *)(MCF_MBAR + MCFPP_DAT)) = \
//		*((volatile unsigned char *)(MCF_MBAR + MCFPP_DAT)) &
//(0xff-ds1302_bit); \ 	  else \
//		*((volatile unsigned char *)(MCF_MBAR + MCFPP_DAT)) = \
//		*((volatile unsigned char *)(MCF_MBAR + MCFPP_DAT)) |
//ds1302_bit; \ 	}
#define DS1302IN(ds1302_bit) (*((volatile unsigned char *)(MCF_MBAR + MCFPP_PPDAT)) & ds1302_bit)

//local storage
TIME_STRUCT ds_1302_time;						/* copy of system time */

//write
void DS1302(unsigned char ds1302_bit,unsigned int logical_value)
	{ 
	if (!logical_value)
		*((volatile unsigned char *)(MCF_MBAR + MCFPP_PPDAT)) =
			*((volatile unsigned char *)(MCF_MBAR +MCFPP_PPDAT))& (0xff-ds1302_bit);
		else
		*((volatile unsigned char *)(MCF_MBAR + MCFPP_PPDAT)) =
		*((volatile unsigned char *)(MCF_MBAR +MCFPP_PPDAT))|ds1302_bit;
	}


/*******************************************************************
	Setup_1302_Port
	
	Initialize Port Pins to access DS1302 Clock.

	Note that all three pins are defined initialliy as outputs.
	When you want to read a port pin, you have to turn it
	around.

	MCF5206...
	PP0 = CLOCK
	PP1 = RST*
	PP2 = DATA
********************************************************************/
void Setup_1302_Port(void)
   {
	unsigned char c;
	//get the current value of the Pin Assignment Register
	c = *(volatile unsigned char *)(MCF_MBAR + MCFSIM_PAR);
	c = c & 0xef;	//PAR4 = 0, selects PP0-4 on port instead of 
						//BDM PST0-3
	*(volatile unsigned char *)(MCF_MBAR + MCFSIM_PAR) = c;
	//and make sure that we have the appropriate direction for
	//the port pins
	c = *(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR);
	c = c | (CLK_1302 + RST_1302 + DAT_1302);	//selects all output
	*(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR) = c;
	
	Idle_1302();			/* set the port pins idle */
	return;
	} //end proc Setup_1302_Port()

/*******************************************************************
	Read_1302_Port
	
	MCF5206...
	PP0 = RESET*
	PP1 = CLOCK
	PP2 = DATA
********************************************************************/
unsigned char Read_1302_Port(void)
   {
	unsigned char c;

	c = *(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDAT);
	c = c & (CLK_1302 + RST_1302 + DAT_1302);//three DS1302 lines only
//	c = *(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR);
	return(c);
	} //end proc Read_1302_Port()


/*******************************************************************
	Read_1302_Data

	Reads all 8 bytes of data from the DS1302.
	Inputs: 	TimeBuffer- Pointer to 8 byte unsigned char array where data
				will be placed once read from the clock
	Returns in TimeBuffer:
	TimeBuffer[0]	seconds: msb=1, clock hold, BCD seconds
	TimeBuffer[1]	minutes: 0,BCD minutes
	TimeBuffer[2]	hours:   msb=1,12 hour/0,24 hour, BCD hour
				msb=0,	0-23 BCD
				msb=1,  {10}{0=am/1=pm}01-12 BCD
	TimeBuffer[3]	day of month: BCD day 0-31
	TimeBuffer[4]	month:	BCD 1-12
	TimeBuffer[5]	day of week: BCD 1-7 1=Sunday
	TimeBuffer[6]	year: BCD 00-99
	TimeBuffer[7]	write protect: msb=1, write protect
						 msb=0, write en
	returns: 0 if all is well, non-zero if clock was stopped
	NOTE: If clock was stopped, returns non-zero and time is
			indicated as Jan 1, 1999, 12:00:00 Noon
********************************************************************/
unsigned int Read_1302_Data(unsigned char * TimeBuffer)
	{
	unsigned char Cmd_Byte;				/*clock command*/
	unsigned char databyte;         	/*temp data byte*/
  	unsigned char shifter;				/* bit selector */
	unsigned int i,j;
	unsigned char c;

	DS1302(CLK_1302,LOW);
	DS1302(DAT_1302,LOW);
	DS1302(RST_1302,HIGH);
	
	Cmd_Byte = READ_CMD; /* set command to the 1302 for burst read operation */
	shifter = 0x01; 
   for(i=0; i<8; i++)		/* shift the read command */
   	{
		if (shifter & Cmd_Byte)
			DS1302(DAT_1302,HIGH);
		  else
	 		DS1302(DAT_1302,LOW); /* set up the data line */ 
		DS1302(CLK_1302,HIGH);
      shifter = shifter << 1;
      DS1302(CLK_1302,LOW);	/* toggle the clock */
   	} //next i

//	//PB5 (DATA Line) is input
//   write_word_port((unsigned long)(PIO_PBDDR+OCP_BASE),
//	read_word_port((unsigned long)(PIO_PBDDR+OCP_BASE)) & (65535-DAT_1302));

	//and make sure that we have the appropriate direction for
	//the data port pin - to INPUT
	c = *(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR);
	c = c & (0xff - DAT_1302);	//selects data line as input
	*(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR) = c;

   for(i=0; i<8; i++)		/* read in the next 7 bytes returned */
   	{
      databyte = 0;             /* start clean */
      for(j=0; j<8; j++)	/* read in a byte */
      	{
      	//make room for the new bit
      	databyte = databyte >> 1; /* shift the collected data right */
      	if (DS1302IN(DAT_1302))
	 			databyte |= 0x80;
			  else
	 			databyte &= 0x7f;    /* capture the state of the data line */

      	DS1302(CLK_1302,HIGH);
      	DS1302(CLK_1302,LOW);	/* clock the chip */
      	} //next j
      TimeBuffer[i] = databyte;	/* save it in the buffer */
   	} //next i

//   //PB5 (DATA Line) is output
//   write_word_port((unsigned long)(PIO_PBDDR+OCP_BASE),
//	read_word_port((unsigned long)(PIO_PBDDR+OCP_BASE)) | DAT_1203);

	//and make sure that we have the appropriate direction for
	//the data port pin - back to OUTPUT
	c = *(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR);
	c = c  | DAT_1302;	//selects data line as output
	*(volatile unsigned char *)(MCF_MBAR + MCFPP_PPDDR) = c;

	Idle_1302();			/* set the port pins idle */

	//clean-up of time if time is bad (like when clock is stopped...)
	if (TimeBuffer[0] > 0x59)
		{
		//The time is bogus, make an assumption
		TimeBuffer[5] = 4;		//day of week: BCD 1-7 1=Sunday
		TimeBuffer[6] = 0x99;	//year: BCD 00-99
		TimeBuffer[4] = 0x1;		//month:	BCD 1-12
		TimeBuffer[3] = 0x1;		//day of month: BCD day 0-31
		TimeBuffer[1] = 0x00;	//minutes: 0,BCD minutes
		TimeBuffer[2] = 0x12;	//hours:   msb=1,12 hour/0,24 hour, BCD hour
										//msb=0,	0-23 BCD
										//msb=1,  {10}{0=am/1=pm}01-12 BCD
		TimeBuffer[0] = 0;		//0 sec
										//seconds: msb=1, clock hold, BCD seconds
		return(1);	//indicate that clock was stopped
		} //end if (TimeBuffer[0] > 59)
	return(0);	//indicate that clock is running
	} /* end Read_1302_Data() */


/********************************************************************
	WRITE_1302_Data

	This routine will write all 8 bytes to the 1302 clock chip.
	Inputs: 	TimeBuffer- Pointer to 8 byte unsigned char array where data
				will be placed once read from the clock
	Obtains from TimeBuffer:
	TimeBuffer[0]	seconds: msb=1, clock hold, BCD seconds
	TimeBuffer[1]	minutes: 0,BCD minutes
	TimeBuffer[2]	hours:   msb=1,12 hour/0,24 hour, BCD hour
				msb=0,	0-23 BCD
				msb=1,  {10}{0=am/1=pm}01-12 BCD
	TimeBuffer[3]	day of month: BCD day 0-31
	TimeBuffer[4]	month:	BCD 1-12
	TimeBuffer[5]	day of week: BCD 1-7 1=Sunday
	TimeBuffer[6]	year: BCD 00-99
	TimeBuffer[7]	write protect: msb=1, write protect
				       msb=0, write en
	Returns: None
*********************************************************************/
void Write_1302_Data(unsigned char * TimeBuffer)
	{
	unsigned char Cmd_Byte;				/*clock command*/
	unsigned char databyte;         	/*temp data byte*/
  	unsigned char shifter;				/* bit selector */
  	unsigned int i,j;

   DS1302(CLK_1302,LOW);
   DS1302(DAT_1302,LOW);
   DS1302(RST_1302,HIGH);

   Cmd_Byte = WRITE_CMD;	/* set command to the 1302 for
   								burst write operation */
   shifter = 0x01;

   for(i=0; i<8; i++)		/* shift out the command */
   	{
      if (shifter & Cmd_Byte)
	 		DS1302(DAT_1302,HIGH);
		  else
	 		DS1302(DAT_1302,LOW);	/* set up the data port pin */

      DS1302(CLK_1302,HIGH);
      shifter = shifter << 1;
      DS1302(CLK_1302,LOW);		/* clock the chip */
   	} //next i

   for(i=0; i<8; i++)		/* output all 8 bytes to DS1302 */
   	{
      shifter = 0x01;
      databyte = TimeBuffer[i];  /* get byte from buffer */
      for(j=0; j<8; j++)	/* shift out data */
      	{
      	if (shifter & databyte)
	 			DS1302(DAT_1302,HIGH);
			  else
	 			DS1302(DAT_1302,LOW);	/* set up the data port pin */

	      DS1302(CLK_1302,HIGH);
      	shifter = shifter << 1;
      	DS1302(CLK_1302,LOW);		/* clock the chip */
      	} //next j
   	} //next i

   Idle_1302();			/* set the port pins idle */
	return;
	} /* end Write_1302_Data() */

/*******************************************************************
	Enable_1302

	Write enables the Dallas Semi 1302 clock chip.

********************************************************************/
void Enable_1302(void)
	{
	unsigned char Cmd_Byte;				/*clock command*/
	unsigned char databyte;         	/*temp data byte*/
	unsigned char shifter;				/* bit selector */
	unsigned int i,j;
	
	DS1302(CLK_1302,LOW);
   DS1302(DAT_1302,LOW);
   DS1302(RST_1302,HIGH);

   Cmd_Byte = 0x8e;		/* set command to the 1302 for
   							write to write prot register */
   shifter = 0x01;

   for(i=0; i<8; i++)	/* shift out the command */
   	{
      if (shifter & Cmd_Byte)
	 		DS1302(DAT_1302,HIGH);
		  else
	 		DS1302(DAT_1302,LOW);

      DS1302(CLK_1302,HIGH);
      shifter = shifter << 1;
		DS1302(CLK_1302,LOW);
   	} //next i


   shifter = 0x01;
   databyte =0;			/* we want to write enable the
								DS1302 chip */

   for(j=0; j<8; j++)	/* shift out the data */
   	{
      if (shifter & databyte)
	 		DS1302(DAT_1302,HIGH);
		  else
	 		DS1302(DAT_1302,LOW);

      DS1302(CLK_1302,HIGH);
      shifter = shifter << 1;
      DS1302(CLK_1302,LOW);		/* clock the chip */
   	} //next j

   Idle_1302();			/* idle the port pins */
	return;
	} /* end Enable_1302() */

/*******************************************************************
	Idle_1302

	This routine will set the port pins that drive the clock to
	their idle states.
********************************************************************/
void Idle_1302(void)
	{
   DS1302(RST_1302,LOW);
   DS1302(DAT_1302,HIGH);
   DS1302(CLK_1302,HIGH);
	return;
	} /* end Idle_1302() */

/*******************************************************************
	Lock_1302

	This routine will LOCK the clock and stop its oscillator to
	preserve Battery Life.
	Uses TimeBuffer[] as temporary storage.
********************************************************************/
void Lock_1302 (void)
   {
	unsigned char TimeBuffer[8];				//temp storage

   Read_1302_Data(&TimeBuffer[0]);        //get the time
	TimeBuffer[0] = TimeBuffer[0]|0x80;    //halt the clock
   Enable_1302();    							//write enable the clock
	Write_1302_Data(&TimeBuffer[0]);       //write back the halted time
	return;
   } /* end proc Lock_1203() */


/*******************************************************************
	Set_Time

	This routine SETs the clock and start its oscillator, write-
	protecting the clock registers.
	Obtains time from TimeBuffer[].
********************************************************************/
void Set_Time(unsigned char * TimeBuffer)
   {
   TimeBuffer[7] = '\x80';         //write protect the chip after write
   Enable_1302();                  //write enable the clock
   Write_1302_Data(TimeBuffer);              //write the clock and start it up
   } /* end proc Set_Time() */

/*******************************************************************
	Get_Time

	This routine GETs the time from the Dallas 1302 clock.
	The time is returned in TimeBuffer.
	This function returns 0 when the clock is operating properly.
	If the clock was locked (stopped) the default time is returned
	as 1/1/99, 12:00Noon and the function returns non-zero.
********************************************************************/
unsigned int Get_Time(unsigned char * TimeBuffer)
   {
	unsigned int clock_locked;
	
	//get the time and put it in TimeBuffer[]
	clock_locked = Read_1302_Data(TimeBuffer);	
	//store the time in system variable time....
	//Note that since the values in the RTC and TimeBuffer are in
	//BCD, we need to convert back to normal numbers!
	ds_1302_time.year = (((TimeBuffer[6] & 0xf0)>>4)*10)+(TimeBuffer[6] & 0xf);
	ds_1302_time.month = (((TimeBuffer[4] & 0xf0)>>4)*10)+(TimeBuffer[4] & 0xf);
	ds_1302_time.date = (((TimeBuffer[3] & 0xf0)>>4)*10)+(TimeBuffer[3] & 0xf);
	ds_1302_time.hour = (((TimeBuffer[2] & 0x30)>>4)*10)+(TimeBuffer[2] & 0xf);
	ds_1302_time.min = (((TimeBuffer[1] & 0xf0)>>4)*10)+(TimeBuffer[1] & 0xf);
	ds_1302_time.sec = (((TimeBuffer[0] & 0xf0)>>4)*10)+(TimeBuffer[0] & 0xf);
	ds_1302_time.dayOfWeek = TimeBuffer[5];
	return(clock_locked);
	} /* end proc Get_Time() */


