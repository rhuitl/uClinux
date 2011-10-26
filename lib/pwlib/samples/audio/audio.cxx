//
// audio.cxx
//
// Roger Hardiman
//
//
/*
 * audio.cxx
 *
 * PWLib application source file for audio testing.
 *
 * Main program entry point.
 *
 * Copyright 2005 Roger Hardiman
 *
 * Copied by Derek Smithies, 1)Add soundtest code from ohphone.
 *                           2)Add headers.
 *
 * $Log: audio.cxx,v $
 * Revision 1.5  2005/11/30 12:47:39  csoutheren
 * Removed tabs, reformatted some code, and changed tags for Doxygen
 *
 * Revision 1.4  2005/08/18 22:29:15  dereksmithies
 * Add a full duplex sound card test (which was excised from ohphone).
 * Add copyright header and cvs log statements.
 * Fix startup and closedown segfaults.
 * Add safety mechanism so it can never fill up all computer memory.
 *
 *
 *
 *
 */

#include <ptlib.h>
#include "version.h"
#include "audio.h"

Audio::Audio()
  : PProcess("Roger Hardiman & Derek Smithies code factory", "audio",
             MAJOR_VERSION, MINOR_VERSION, BUILD_TYPE, BUILD_NUMBER)
{

}

PCREATE_PROCESS(Audio)

void Audio::Main()
{
  PArgList & args = GetArguments();
  args.Parse("r.    "
       "f.    "
       "h.    "
#if PTRACING
             "o-output:"             "-no-output."
             "t-trace."              "-no-trace."
#endif
       "v.    "
       "s:    ");
 
  if (args.HasOption('h')) {
    cout << "usage: audio " 
         << endl
         << "     -r        : report available sound devices" << endl
         << "     -f.       : do a full duplex sound test on a sound device" << endl
         << "     -s  dev   : use this device in full duplex test " << endl
         << "     -h        : get help on usage " << endl
         << "     -v        : report program version " << endl
#if PTRACING
         << "  -t --trace   : Enable trace, use multiple times for more detail" << endl
         << "  -o --output  : File for trace output, default is stderr" << endl
#endif
         << endl;
    return;
  }


  PTrace::Initialise(args.GetOptionCount('t'),
                     args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL,
         PTrace::Blocks | PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine);

  if (args.HasOption('v')) {
    cout << endl
         << "Product Name: " <<  (const char *)GetName() << endl
         << "Manufacturer: " <<  (const char *)GetManufacturer() << endl
         << "Version     : " <<  (const char *)GetVersion(TRUE) << endl
         << "System      : " <<  (const char *)GetOSName() << '-'
         <<  (const char *)GetOSHardware() << ' '
         <<  (const char *)GetOSVersion() << endl
         << endl;
    return;
  }
  

  cout << "Audio Test Program\n";

  PSoundChannel::Directions dir;
  PStringArray namesPlay, namesRecord;

  cout << "\n";
  cout << "List of play devices\n";

  dir = PSoundChannel::Player;
  namesPlay = PSoundChannel::GetDeviceNames(dir);
  for (PINDEX i = 0; i < namesPlay.GetSize(); i++)
    cout << "  \"" << namesPlay[i] << "\"\n";

  cout << "The default play device is \"" << PSoundChannel::GetDefaultDevice(dir) << "\"\n";


  cout << "\n";
  cout << "List of Record devices\n";

  dir = PSoundChannel::Recorder;
  namesRecord = PSoundChannel::GetDeviceNames(dir);
  for (PINDEX i = 0; i < namesRecord.GetSize(); i++)
    cout << "  \"" << namesRecord[i] << "\"\n";

  cout << "The default record device is \"" << PSoundChannel::GetDefaultDevice(dir) << "\"\n";

  cout << "\n";


  // Display the mixer settings for the default devices
  PSoundChannel sound;
  dir = PSoundChannel::Player;
  sound.Open(PSoundChannel::GetDefaultDevice(dir),dir);

  unsigned int vol;
  if (sound.GetVolume(vol))
    cout << "Play volume is (for the default play device)" << vol << endl;
  else
    cout << "Play volume cannot be obtained" << endl;

  sound.Close();

  dir = PSoundChannel::Recorder;
  sound.Open(PSoundChannel::GetDefaultDevice(dir),dir);
  
  if (sound.GetVolume(vol))
    cout << "Record volume is (for the default record device)" << vol << endl;
  else
    cout << "Record volume cannot be obtained" << endl;

  sound.Close();


  if (args.HasOption('f')) {
    devName = args.GetOptionString('s');
    if (devName.IsEmpty())
      devName = PSoundChannel::GetDefaultDevice(PSoundChannel::Player);

    if (namesPlay.GetStringsIndex(devName) == P_MAX_INDEX) {
      cout << "could not find " << devName << " in list of available play devices - abort test" << endl;
      return;
    }

    if (namesRecord.GetStringsIndex(devName) == P_MAX_INDEX) {
      cout << "could not find " << devName << " in list of available record devices - abort test" << endl;
      return;
    }

    PTRACE(3, "Audio\tTest device " << devName);
    
    TestAudioDevice device;
    device.Test();
      return;
  }

#if PTRACING
  if (args.GetOptionCount('t') > 0) {
    PTrace::ClearOptions(0);
    PTrace::SetLevel(0);
  }
#endif

}

////////////////////////////////////////////////////////////////////////////////

TestAudioDevice::~TestAudioDevice()
{
  AllowDeleteObjects();
  access.Wait();
  RemoveAll();
  endNow = TRUE;
  access.Signal();
  PThread::Sleep(100);
}

void TestAudioDevice::Test()
{
   endNow = FALSE;
   PConsoleChannel console(PConsoleChannel::StandardInput);

   AllowDeleteObjects(FALSE);
   PTRACE(3, "Start operation of TestAudioDevice");

   TestAudioRead reader(*this);
   TestAudioWrite writer(*this);   


   PStringStream help;
   help << "Select:\n";
   help << "  X   : Exit program\n"
        << "  Q   : Exit program\n"
        << "  {}  : Increase/reduce record volume\n"
        << "  []  : Increase/reduce playback volume\n"
        << "  H   : Write this help out\n";
   
   PThread::Sleep(100);
   if (reader.IsTerminated() || writer.IsTerminated()) {
     reader.Terminate();
     writer.Terminate();
     
     goto endAudioTest;
   }

  for (;;) {
    // display the prompt
    cout << "(testing sound device for full duplex) Command ? " << flush;

    // terminate the menu loop if console finished
    char ch = (char)console.peek();
    if (console.eof()) {
      cout << "\nConsole gone - menu disabled" << endl;
      goto endAudioTest;
    }

    console >> ch;
    PTRACE(3, "console in audio test is " << ch);
    switch (tolower(ch)) {
      case '{' : 
        reader.LowerVolume();
        break;
      case '}' :
        reader.RaiseVolume();
        break;
      case '[' :
        writer.LowerVolume();
        break;
      case ']' : 
        writer.RaiseVolume();
        break;
      case 'q' :
      case 'x' :
        goto endAudioTest;
      case 'h' :
        cout << help ;
      break;
        default:
          ;
    }
  }

endAudioTest:
  endNow = TRUE;
  cout  << "end audio test" << endl;

  reader.WaitForTermination();
  writer.WaitForTermination();
}


PBYTEArray *TestAudioDevice::GetNextAudioFrame()
{
  PBYTEArray *data = NULL;

  while (data == NULL) {
    {
      PWaitAndSignal m(access);
      if (GetSize() > 30)
        data = (PBYTEArray *)RemoveAt(0);  
      if (endNow)
        return NULL;
    }

    if (data == NULL) {
      PThread::Sleep(30);
    }
  }
  
  return data;
}

void TestAudioDevice::WriteAudioFrame(PBYTEArray *data)
{
  PWaitAndSignal mutex(access);
  if (endNow) {
    delete data;
    return;
  }
  
  PTRACE(5, "Buffer\tNow put one frame on the que");
  Append(data);
  if (GetSize() > 50) {
    cout << "The audio reader thread is not working - exit now before memory is exhausted" << endl;
    endNow = TRUE;
  }
  return;
}

BOOL TestAudioDevice::DoEndNow()
{
    return endNow;
}

//////////////////////////////////////////////////////////////////////

TestAudioRead::TestAudioRead(TestAudioDevice &master)
       :TestAudio(master)
{    
  PTRACE(3, "Reader\tInitiate thread for reading " );
}

void TestAudioRead::Main()
{
  if (!OpenAudio(PSoundChannel::Recorder)) {
    PTRACE(1, "TestAudioWrite\tFAILED to open read device");
    return;
  }

  PTRACE(3, "TestAduioRead\tSound device is now open, start running");

  while ((!controller.DoEndNow()) && keepGoing) {
    PBYTEArray *data = new PBYTEArray(480);
    sound.Read(data->GetPointer(), data->GetSize());
    PTRACE(3, "TestAudioRead\t send one frame to the queue" << data->GetSize());
    controller.WriteAudioFrame(data);
  }
  
  PTRACE(3, "End audio read thread");
}

//////////////////////////////////////////////////////////////////////

TestAudioWrite::TestAudioWrite(TestAudioDevice &master)
   : TestAudio(master)
{
  PTRACE(3, "Reader\tInitiate thread for writing " );
}

void TestAudioWrite::Main()
{
  if (!OpenAudio(PSoundChannel::Player)) {
    PTRACE(1, "TestAudioWrite\tFAILED to open play device");
    return;
  }
  PTRACE(3, "TestAudioWrite\tSound device is now open, start running");    
  
  while ((!controller.DoEndNow()) && keepGoing) {
    PBYTEArray *data = controller.GetNextAudioFrame();
    PTRACE(3, "TestAudioWrite\tHave read one audio frame ");
    if (data != NULL) {
      sound.Write(data->GetPointer(), data->GetSize());
      delete data;
    } else
      PTRACE(1, "testAudioWrite\t next audio frame is NULL");    
  }


  PTRACE(3, "End audio write thread");
}

//////////////////////////////////////////////////////////////

TestAudio::TestAudio(TestAudioDevice &master) 
    :PThread(1000, NoAutoDeleteThread),
     controller(master)
{
  keepGoing = TRUE;
  Resume();
}

TestAudio::~TestAudio()
{
   sound.Close();
}


BOOL TestAudio::OpenAudio(enum PSoundChannel::Directions dir)
{
  if (dir == PSoundChannel::Recorder) 
    name = "Recorder";
  else
    name = "Player";
  
  PThread::Current()->SetThreadName(name);
  PString devName = Audio::Current().GetTestDeviceName();
  PTRACE(3, "TestAudio\t open audio start for " << name << " and device name of " << devName);

  PTRACE(3, "Open audio device for " << name << " and device name of " << devName);
  if (!sound.Open(devName,
      dir,
      1, 8000, 16)) {
    cerr <<  "TestAudioRead:: Failed to open sound Playing device. Exit" << endl;
    PTRACE(3, "TestAudio\tFailed to open device for " << name << " and device name of " << devName);

    return FALSE;
  }
  
  currentVolume = 90;
  sound.SetVolume(currentVolume);
  
  sound.SetBuffers(480, 3);
  return TRUE;
}


void TestAudio::RaiseVolume()
{
   if ((currentVolume + 5) < 101)
     currentVolume += 5;
   sound.SetVolume(currentVolume);
   cout << name << " volume is " << currentVolume << endl;
   PTRACE(3, "TestAudio\tRaise volume for " << name << " to " << currentVolume);
}

void TestAudio::LowerVolume()
{
   if ((currentVolume - 5) >= 0)
     currentVolume -= 5;
   sound.SetVolume(currentVolume);
   cout << name << " volume is " << currentVolume << endl;
   PTRACE(3, "TestAudio\tLower volume for " << name << " to " << currentVolume);
}
////////////////////////////////////////////////////////////////////////////////


// End of hello.cxx
