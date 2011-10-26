/*
 * cu30codec.cxx
 *
 * H.323 protocol handler
 *
 * Open H323 Library
 *
 * Copyright (c) 1998-2000 Equivalence Pty. Ltd.
 *
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is Open H323 Library.
 *
 * The Initial Developer of the Original Code is Equivalence Pty. Ltd.
 *
 * Contributor(s): Derek J Smithies (derek@indranet.co.nz)
 *                 ______________________________________
 *                
 * $Log: cu30codec.cxx,v $
 * Revision 1.6  2005/06/07 07:59:11  csoutheren
 * Applied patch 1176459 for PocketPC. Thanks to Matthias Weber
 *
 * Revision 1.5  2002/12/29 22:35:52  dereks
 * Fix so it compiles.
 *
 * Revision 1.4  2002/10/09 18:18:35  rogerh
 * Apply a patch from Damien Sandras
 *
 * Revision 1.3  2002/08/05 10:03:47  robertj
 * Cosmetic changes to normalise the usage of pragma interface/implementation.
 *
 * Revision 1.2  2002/01/16 02:53:52  dereks
 * Add methods to cope with H.245 RequestModeChange in h.261 video codec.
 *
 * Revision 1.1  2001/10/23 02:17:16  dereks
 * Initial release of cu30 video codec.
 *
 *
 *
 * Notes on the operation of this codec.
 * A library is dynamically allocated by the PDynaLink class (which is 
 *   an ancestor of the H323_Cu30Codec class.
 * 
 * If multiple threads each open the library, there is only one instance of the library.
 * The library requires some classes to be allocated to run, where these classes are 
 * specific to the thread opening the library. We therefore call the library, and request
 * it to allocate some internal data - which is specific to this thread.
 *
 *
 * the cu30codec 
 *        -must create (and free) data specific to this thread
 * the cu30encoder
 *        -must create/delete the yuv420pImage
 *        -must not create/delete the encodedImage.
 * the cu30decoder
 *        -must not create/delete the yuv420pImage.
 *        -must create/delete the encodedImage.
 *
 * Alternatively, the cu30codec must make the image used as the source 
 *   so the encoder must make/delete the yuv420pImage.
 *           cu30encoder(library routine) makes/deletes the encodedImage.
 */

#include <ptlib.h>

#ifdef __GNUC__
#pragma implementation "cu30codec.h"
#endif

#include "cu30codec.h"

#include "rtp.h"
#include "h245.h"


#define new PNEW


enum { 
  SamplesPerFrame = 180,    // 22.5 milliseconds
  BitsPerFrame = 54,        // Encoded size
  BytesPerFrame = (BitsPerFrame+7)/8
};


/*
static OpalMediaFormat const Cu30_MediaFormat("Cu30",
					      OpalMediaFormat::DefaultVideoSessionID,
                                              RTP_DataFrame::DynamicBase,
                                              FALSE,     // Use jitter to order packets.(should be true,
					                 // but that implies we are an audio codec).
                                              240000,   // bits/sec        
                                              100000,   // Max Frame Size.
                                              0,        // No intrinsic time per frame.
                                              OpalMediaFormat::VideoTimeUnits);
*/


H323_Cu30Capability::H323_Cu30Capability(H323EndPoint & endpoint,
                                         PString        statsDir,
					 INT            _width,
					 INT            _height,
					 INT            _statsFrames)
  : H323NonStandardVideoCapability(endpoint, (const BYTE *)"Cu30", 4,0,4)
{
  statisticsDir = statsDir;  
  newWidth      = _width;
  newHeight     = _height;
  statsFrames   = _statsFrames;
}


PObject * H323_Cu30Capability::Clone() const
{
  return new H323_Cu30Capability(*this);
}


PString H323_Cu30Capability::GetFormatName() const
{
  return "Cu30{sw}";
}


H323Codec * H323_Cu30Capability::CreateCodec(H323Codec::Direction direction) const
{
  return new H323_Cu30Codec(direction,statisticsDir,newWidth,newHeight,statsFrames);
}


/////////////////////////////////////////////////////////////////////////////
const int MaxRtpPacketSize = 1400;

H323_Cu30Codec::H323_Cu30Codec(Direction dir, PString statsDir, 
                               INT _width, INT _height, INT _statsFrames)
  :  H323VideoCodec("Cu30", dir),  PDynaLink("libcu30.so.0")
{
  yuv420pImage = NULL;
  encodedImage = NULL;
  encodedImageSize  = 0;
  encodedImageIndex = 0;    
  packetCount       = 0;
  codecActive       = FALSE;

  if (!IsLoaded()) {
    PDynaLink::Close();
    PTRACE(0,"Cu30\t failed to load external Library. Prepare for doom");
    cerr << "ERROR.. Failed to load the libcu30.so.0 external library"<<endl;
    cerr << "ERROR.. Try setting library path variables."<<endl;
#ifdef _WIN32
	Sleep(1000);
#else
    sleep(1); // This has to be handled better than the above code..
#endif
    return;
  }

  if(!( GetFunction("Cu30SetQuality",       (Function &)SetQuality      ) &&
	GetFunction("Cu30CopyStatsToLib",   (Function &)CopyStatsToLib  ) &&
	GetFunction("Cu30CopyStatsFromLib", (Function &)CopyStatsFromLib) &&

	GetFunction("Cu30OpenStats",        (Function &)OpenStats       ) &&
	GetFunction("Cu30CloseStats",       (Function &)CloseStats      ) &&
	GetFunction("Cu30DoStats",          (Function &)DoStats         ) &&
	GetFunction("Cu30SendStatsToFiles", (Function &)SendStatsToFiles) &&

	GetFunction("Cu30OpenEncoderWith",  (Function &)OpenEncoderWith ) &&
	GetFunction("Cu30OpenEncoder",      (Function &)OpenEncoder     ) &&
	GetFunction("Cu30CloseEncoder",     (Function &)CloseEncoder    ) &&
	GetFunction("Cu30DoEncode",         (Function &)DoEncode        ) &&
	GetFunction("Cu30SetCodecSize",     (Function &)SetCodecSize    ) &&

	GetFunction("Cu30OpenDecoder",      (Function &)OpenDecoder     ) &&
	GetFunction("Cu30CloseDecoder",     (Function &)CloseDecoder    ) &&
	GetFunction("Cu30DoDecode",         (Function &)DoDecode        ) &&

	GetFunction("Cu30IsIntraFrame",     (Function &)IsIntraFrame    ) &&
	GetFunction("Cu30ForceIntraFrame",  (Function &)ForceIntraFrame ) &&
	GetFunction("Cu30MakeInternalData", (Function &)MakeInternalData) &&
	GetFunction("Cu30FreeInternalData", (Function &)FreeInternalData) &&
        GetFunction("Cu30StatsLoadedOK",    (Function &)StatsLoadedOK   )    )) 
    {
      PDynaLink::Close();    
      PTRACE(0,"Cu30\t failed to load functions in external Library.");
      cerr << "Cu30\t failed to load functions in  external Library." << endl;
#ifdef _WIN32
	  Sleep(2000);
#else
      sleep(2);
#endif
    }

  frameWidth  = _width;
  frameHeight = _height;
  statsFrames = _statsFrames;

  MakeInternalData(&internData);
  
  AllocateInternalImages();
  statisticsDir = statsDir; 
  resendStats   = FALSE;

  PTRACE(3, "Cu30\t library " << (dir == Encoder ? "EN" : "DE")
         << "coder opened. ");
  if(dir == Encoder)
    PTRACE(3,"Cu30\t  width is "<<_width<<"x"<<_height);


  if(statsFrames) {
    if(OpenStats(internData,frameWidth,frameHeight)) 
      PTRACE(3,"Cu30\t  Succesfully opened stats collection. " <<
	     "FrameSize is " << frameWidth << "x" << frameHeight << ". " <<
             "Collect data for " << statsFrames << " frames." );    
  }

  waitForIntraFrame = FALSE;
}


H323_Cu30Codec::~H323_Cu30Codec()
{   
  Close();

  FreeInternalData(internData);
}

/* The generated Cu30packet starts with three pindex bytes.
   pindex 0 == frame width
          1 == frame height
          2 == position in the encoded image this packet goes to.
    and then packet data.

   For the case where the statistics fields are being sent, which is the first
   four packets communicated from one end to the other, it is
    pindex 0 == marker number to say statistics,
           1 == 1,2,3,4 to indicate y u v mc respectively
           3 == not used (consistancy)
   and then the statistics data.
*/

BOOL H323_Cu30Codec::Read(BYTE * buffer,
                          unsigned & length,
                          RTP_DataFrame & frame)
{
  PWaitAndSignal mutex1(videoHandlerActive);  

  if(!IsLoaded()) {
    PTRACE(0,"Cu30\t FAILED to load the cu30codec library. EXIT GRAB process");
    return 0;
  }

  PTRACE(6,"Cu30\t  Read one video packet from codec/grabber. Invocation #"<<packetCount);
  length = 0;

  frameWidth  = ((PVideoChannel *)rawDataChannel)->GetGrabWidth();
  frameHeight = ((PVideoChannel *)rawDataChannel)->GetGrabHeight();

  if( (frameWidth <= 0) || (frameHeight <= 0) ) {
    PTRACE(3,"Cu30\t  Video grab width is " <<  frameWidth <<"x"<< frameHeight);    
    PTRACE(3,"Cu30\t  Close down video transmission thread.");
    return FALSE;
  } 

  Resize(frameWidth, frameHeight); 
  SetQuality(internData, videoQuality);

  if(codecActive==FALSE) {
    PTRACE(3,"Cu30\t  about to open encoder. Initial size "
                           <<frameWidth<<"x"<<frameHeight);
    PTRACE(3,"Cu30\t  about to open encoder "<<statisticsDir);       
    if(OpenEncoderWith(internData,frameWidth,frameHeight, statisticsDir.GetPointer() ) == 0){
      PTRACE(3,"Cu30\t failed to open encoder." );
      return 0;      
    }
    
    codecActive= TRUE;
    SetQuality(internData, videoQuality);
  }

  packetCount++;

  if(resendStats) {
    packetCount = 1;
    resendStats = FALSE;
  }

  if(packetCount<5) { // Must send one of the four statistics fields.
    PINDEX *headerStats;

    headerStats = (PINDEX *)buffer;
    *headerStats = 0;
    headerStats++;

    *headerStats = packetCount;  
    headerStats++;

    *headerStats =  0;    //This line is not needed.
    headerStats++;

    BYTE * cu30Data = (BYTE *)headerStats;

    //packetCount determines if it is Y, U, V, or MC field.
    PTRACE(3,"Cu30\t Statistics for field (y u v mc == 1..4) "<<packetCount);
    switch (packetCount) {    
    case 1: CopyStatsFromLib(internData, cu30Data, length, "y");
      break;
    case 2: CopyStatsFromLib(internData, cu30Data, length, "u");
      break;
    case 3: CopyStatsFromLib(internData, cu30Data, length, "v");
      break;
    case 4: CopyStatsFromLib(internData, cu30Data, length, "mc");
      break;
    default:PTRACE(1,"Cu30\t Error. default case option called.");
    }
    PThread::Current()->Sleep(50);  // Place a 50ms interval between stats.
    length += 3*sizeof (PINDEX);    
    return TRUE;
  }


  if( rawDataChannel == NULL ) {//Some other task has killed our videohandler. Exit.
    PTRACE(3,"Cu30\t  Encoder's raw data channel has been killed. ");
    PTRACE(3,"Cu30\t  Close down video transmission thread.");
    return FALSE;
  }
  
  if( !rawDataChannel->IsOpen()) {
    PTRACE(3,"Cu30\t  Video grabber is not initialised.");
    PTRACE(3,"Cu30\t  Close down video transmission thread.");
    return FALSE;
  }

  PINDEX bytesInFrame=0;
  int bytesRemaining = encodedImageSize-encodedImageIndex;

  if( bytesRemaining==0 ) {  
    //NO data is waiting to be read. Get data with the read call.
      PTRACE(3,"Cu30\t  Finished sending current frame. Get next frame.");
      if(rawDataChannel->Read(yuv420pImage,bytesInFrame)) {
        RecordStatistics(yuv420pImage);

	RenderFrame();                 //display data from grab process.
	encodedImageSize = DoEncode(internData, yuv420pImage,&encodedImage); 
	if (encodedImageSize==0) {
	  PTRACE(3,"Cu30\t  Encoder was closed by another thread. ");	  
	  return FALSE; //The encoder has been shut down. We were not told. Sorry.
	}
	encodedImageIndex=0;      
	bytesRemaining = encodedImageSize;
      } else {
	PTRACE(3,"Cu30\t  Read of video grabber failed. Return False");
	return FALSE;   //Read failed, return false.
      }
  } else
    PThread::Current()->Sleep(5);  // Place a 5 ms interval betwen packets of the same frame.


  PINDEX *statsHeader = (PINDEX *)buffer;  
  *statsHeader = frameWidth;
  statsHeader++;

  *statsHeader = frameHeight;
  statsHeader++;

  *statsHeader = encodedImageIndex;
  statsHeader++;

  BYTE *rtpData = (BYTE *)statsHeader;
  length  = 3*sizeof(PINDEX);

  if (bytesRemaining<0) {
	PTRACE(0,"Cu30\t  Internal ERROR in Cu30 codec. " <<
               "Bytes Remaining is " << bytesRemaining);      
	PTRACE(0,"Cu30\t  Closing video stream transmission");
	return FALSE;
  }

  if( bytesRemaining < MaxRtpPacketSize ) {
    memcpy(rtpData,encodedImage+encodedImageIndex,bytesRemaining);
    length += bytesRemaining; 
    encodedImageIndex = encodedImageSize;    
  } else {
    memcpy(rtpData,encodedImage+encodedImageIndex,MaxRtpPacketSize);
    encodedImageIndex += MaxRtpPacketSize; 
    length += MaxRtpPacketSize;    
  }
    
  frame.SetMarker(encodedImageIndex == encodedImageSize); 
  //an argument of TRUE  means that this is the last packet in frame.
  
  PTRACE(5,"Cu30\t  Finished the read routine. Sent length="<<length<<"\n\n\n");   
  return TRUE;
  }


BOOL H323_Cu30Codec::Write(const BYTE * buffer,
                           unsigned length,
                           const RTP_DataFrame & frame,
                           unsigned & written)
{
  PWaitAndSignal mutex1(videoHandlerActive);  

  if(!IsLoaded()) {
    PTRACE(0,"Cu30\t FAILED to load the cu30codec library. EXIT DISPLAY process");
    return 0;
  }

  PTRACE(5,"Cu30\t Write one video packet to decoder/display. Length="<<length);

  if( rawDataChannel == NULL ) {//Some other task has killed our videohandler. Exit.
    PTRACE(3,"Cu30\t  Decoder's raw data channel has been killed. ");
    PTRACE(3,"Cu30\t  Close down video receive thread.");
    return FALSE;
  }
  
  // always indicate we have written the entire packet
  written = length;

  // buffer is start of Cu30 header
  PINDEX *statsHeader = (PINDEX *)buffer;
  PINDEX _width   = *statsHeader;
  statsHeader++;
  PINDEX _height  = *statsHeader;
  statsHeader++;
  encodedImageIndex = *statsHeader;
  statsHeader++;

  BYTE * header  = (BYTE *)statsHeader;
  length -= 3*sizeof(PINDEX);

  if (_width==0) {  // This is a statistics field.
    PTRACE(3,"Cu30\t Statistics for field (y u v mc == 1..4) "<<_height);
    //_height determines if it is Y, U, V, or MC field.
    switch (_height) {    
    case 1: CopyStatsToLib(internData, header, length, "y");
      break;
    case 2: CopyStatsToLib(internData, header, length, "u");
      break;
    case 3: CopyStatsToLib(internData, header, length, "v");
      break;
    case 4: CopyStatsToLib(internData, header, length, "mc");
      break;
    default: PTRACE(1,"Cu30\t  ERROR. stats field is incorrect");
      PTRACE(3,"Cu30\t  Copy stats to lib Return FALSE == ERROR");   
      return FALSE;      
    }
    if (_height==1)
      packetCount = frame.GetSequenceNumber();
    else
      packetCount++;
    return TRUE;
  }

  if(!StatsLoadedOK(internData)) {
    SendMiscCommand(H245_MiscellaneousCommand_type::e_lostPicture);
    //Cu30 interprets the e_lostPicture command as:: resend the statistics.
    return 1;
  }

  if( (++packetCount) != frame.GetSequenceNumber() ) {
    PTRACE(1,"Cu30\t WARNING. Video packets are being lost in the network somewhere.");
    packetCount = frame.GetSequenceNumber();
    SendMiscCommand(H245_MiscellaneousCommand_type::e_lostPartialPicture);
    waitForIntraFrame = TRUE;
    return TRUE;    //Ignore this packet, because it cannot be correct.
  }

  if(codecActive==FALSE) {
    if(OpenDecoder(internData, _width, _height) == 0) {
      PTRACE(3,"Cu30\t  FAILED to open the decoder. CLose down video receive thread.");
      return 0;
    } 
    PTRACE(3,"Cu30\t Successfully opended the Cu30 decoder");
    codecActive= TRUE;
  }
 
  Resize(_width,_height);
  const BYTE * cu30Data  = header;
  
  memcpy(encodedImage+encodedImageIndex,cu30Data,length);
  BOOL ok=TRUE;

  if (frame.GetMarker()) {//last packet in frame.
    if(waitForIntraFrame && IsIntraFrame(internData, encodedImage))
      waitForIntraFrame = FALSE;

    if(!waitForIntraFrame) {      
      ok = DoDecode(internData, encodedImage, encodedImageIndex + length, &yuv420pImage);    
    }

    if (ok) {
      ok = RenderFrame();
    } else {
      PTRACE(3,"Cu30\t  Some other task has killed our cu30 decoder. Exit");
      return FALSE;
    }
  }

  PTRACE(6,"Cu30\t  Finished write routine.");
  
  return ok;
}

BOOL H323_Cu30Codec::Resize(int _width, int _height)
{
  if( (frameWidth!=_width) || (frameHeight!=_height) ) {
    PTRACE(3,"Cu30\t Detected need to resize to "<<_width<<"x"<<_height);
    frameWidth  = _width;
    frameHeight = _height;
   
    AllocateInternalImages();
    encodedImageIndex=0;
    encodedImageSize=0;

    SetCodecSize(internData, frameWidth, frameHeight);
  }

  return TRUE;
}

BOOL H323_Cu30Codec::RecordStatistics(unsigned char *src)
{
  if(statsFrames>0) {
    DoStats(internData, src);
    statsFrames--;
  }	  
  return statsFrames>0;       // return true if there are more to be done.
}

BOOL H323_Cu30Codec::AllocateInternalImages(void)
{
  if (direction==Encoder) { 
    PTRACE(3,"Cu30\t Allocate Internal Images for ENcoder");
    if (yuv420pImage != NULL){
      PTRACE(3,"Cu30\t delete old yuv420pImage"<<frameWidth<<"x"<<frameHeight);
	delete yuv420pImage;
    }
    if(frameWidth*frameHeight) {
      PTRACE(3,"Cu30\t create new yuv420pImage"<<frameWidth<<"x"<<frameHeight);
      yuv420pImage = new unsigned char[frameWidth*frameHeight*3/2];
      memset(yuv420pImage, 64, frameWidth*frameHeight*3/2);
      } 
  } 

  if (direction==Decoder) {   
    PTRACE(3,"Cu30\t Allocate Internal Images for DEcoder");
    if (encodedImage != NULL) 
	delete encodedImage;

    if(frameWidth*frameHeight) 
      encodedImage = new unsigned char[frameWidth*frameHeight]; //Heaps of space.
  }
  
  return TRUE;
}

BOOL H323_Cu30Codec::Redraw()
{
  return RenderFrame();
}


BOOL H323_Cu30Codec::RenderFrame()
{
 BOOL ok = TRUE;

  if (rawDataChannel != NULL) {
    ((PVideoChannel *)rawDataChannel)->SetRenderFrameSize(frameWidth, frameHeight);
    PTRACE(5, "Cu30\t video rendering frame size is set to " 
	   << frameWidth << "x" << frameHeight);
    ok = rawDataChannel->Write((const void *)yuv420pImage,0);
  }
  return ok;
}

void H323_Cu30Codec::Close()
{
  PTRACE(3,"Cu30\t ::Close()");
  PWaitAndSignal mutex1(videoHandlerActive);  
  PTRACE(3,"Cu30\t ::Close() can now proceed.");
  
  if (!IsLoaded()) 
    return;

  if( direction == Decoder ) {
    CloseDecoder(internData);
    PTRACE(3,"Cu30\t ::CloseDecoder() succeeded.");
    
    if ( encodedImage!=NULL ) {
      delete encodedImage;
      encodedImage = NULL;
    }    
  } 

  if( direction == Encoder ) {
    CloseEncoder(internData);
      
    PFilePath fileName = PProcess::Current().GetConfigurationFile();
    PString statsDir = fileName.GetDirectory();   
    //Statistics files ("y" "u" "v" and "mc") are written here.  
    SendStatsToFiles(internData, statsDir.GetPointer() );
    
    CloseStats(internData);
    PTRACE(3,"Cu30\t ::CloseStats() succeeded");
    
    if ( yuv420pImage!=NULL  ) {
      delete yuv420pImage;
      yuv420pImage = NULL;
      }
  }
  
  encodedImageSize  = 0;
  encodedImageIndex = 0;    
}

void H323_Cu30Codec::OnLostPartialPicture()
{
  if(direction == Encoder) {
    ForceIntraFrame(internData);
    PTRACE(1,"Cu30\t force video encoder to send intra frame");
  } else
    PTRACE(1,"Cu30\t ERR. Receive video codec has OnLostPartialPicture");
}

void H323_Cu30Codec::OnLostPicture()
{
  if(direction == Encoder) {
    resendStats = TRUE;
    PTRACE(1,"Cu30\t force video encoder to send intra frame");
  } else
    PTRACE(1,"Cu30\t ERR. Receive video codec has OnLostPicture");
}

/////////////////////////////////////////////////////////////////////////////
//End of cu30codec.cxx
