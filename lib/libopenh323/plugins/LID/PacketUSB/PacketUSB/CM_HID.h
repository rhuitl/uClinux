
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the CM_HID_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// CM_HID_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef CM_HID_EXPORTS
#define CM_HID_API __declspec(dllexport)
#else
#define CM_HID_API __declspec(dllimport)
#endif

// Functions are exported from the CM_HID.dll
CM_HID_API int StartDeviceDetection(HWND hWnd, DWORD DeviceAddedMsg, DWORD DeviceRemovedMsg, DWORD KeyDownMsg, DWORD KeyUpMsg, DWORD VolumeKeyDownMsg, DWORD VolumeKeyUpMsg, DWORD PlaybackMuteMsg, DWORD RecordMuteMsg);
CM_HID_API int CloseDevice(void);
CM_HID_API void HandleUsbDeviceChange(DWORD wParam, DWORD lParam);
CM_HID_API int StartKeyScan(void);
CM_HID_API int StopKeyScan(void);
CM_HID_API void StartBuzzer(void);
CM_HID_API void StopBuzzer(void);
CM_HID_API void WriteEEPROM(int Address, WORD Value);
CM_HID_API int ReadEEPROM(int Address, WORD *Value);

