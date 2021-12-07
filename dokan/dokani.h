/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2015 - 2019 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
  Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

  http://dokan-dev.github.io

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef DOKANI_H_
#define DOKANI_H_

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <stdio.h>

#include "dokan.h"
#include "dokanc.h"
#include "list.h"

// In appveyor FUSE gets compiled using GCC in Cygwin which doesn't recognize
// the following definitions
#ifndef _MSC_VER

#ifndef _Inout_
#define _Inout_
#endif

#ifndef _Inout_opt_
#define _Inout_opt_
#endif

#ifndef _In_
#define _In_
#endif

#ifndef _Out_
#define _Out_
#endif

#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _DOKAN_INSTANCE_THREADINFO {
	PTP_POOL			ThreadPool;
	PTP_CLEANUP_GROUP	CleanupGroup;
	PTP_IO				IoCompletion;
	TP_CALLBACK_ENVIRON CallbackEnvironment;
} DOKAN_INSTANCE_THREADINFO;

/**
 * \struct DOKAN_INSTANCE
 * \brief Dokan mount instance informations
 *
 * This struct is build from the information provided by the user at DokanMain call.
 * \see DokanMain
 * \see DOKAN_OPTIONS
 * \see DOKAN_OPERATIONS
 */
typedef struct _DOKAN_INSTANCE {
  /** to ensure that unmount dispatch is called at once */
  CRITICAL_SECTION CriticalSection;

  /**
  * Current DeviceName.
  * When there are many mounts, each mount uses different DeviceName.
  */
  WCHAR DeviceName[64];
  /** Mount point. Can be "M:\" (drive letter) or "C:\mount\dokan" (path in NTFS) */
  WCHAR MountPoint[MAX_PATH];
  /** UNC name used for network volume */
  WCHAR UNCName[64];

  /** Device number */
  ULONG DeviceNumber;
  /** Mount ID */
  ULONG MountId;

  /** DOKAN_OPTIONS linked to the mount */
  PDOKAN_OPTIONS DokanOptions;
  /** DOKAN_OPERATIONS linked to the mount */
  PDOKAN_OPERATIONS DokanOperations;

  /** Current list entry informations */
  LIST_ENTRY ListEntry;
  
  HANDLE						GlobalDevice;
  HANDLE						Device;
  HANDLE						DeviceClosedWaitHandle;
  DOKAN_INSTANCE_THREADINFO		ThreadInfo;
  HANDLE						NotifyHandle;
  HANDLE						KeepaliveHandle;

} DOKAN_INSTANCE, *PDOKAN_INSTANCE;

/**
 * \struct DOKAN_OPEN_INFO
 * \brief Dokan open file informations
 *
 * This is created in CreateFile and will be freed in CloseFile.
 */
typedef struct _DOKAN_OPEN_INFO {
  /** DOKAN_OPTIONS linked to the mount */
  BOOL IsDirectory;
  /** Open count on the file */
  ULONG OpenCount;
  /** Event context */
  PEVENT_CONTEXT EventContext;
  /** Dokan instance linked to the open */
  PDOKAN_INSTANCE DokanInstance;
  /** User Context see DOKAN_FILE_INFO.Context */
  ULONG64 UserContext;
  /** Event Id */
  ULONG EventId;
  /** Directories list. Used by FindFiles */
  PLIST_ENTRY DirListHead;
  /** File streams list. Used by FindStreams */
  PLIST_ENTRY StreamListHead;
  /** Used when dispatching the close once the OpenCount drops to 0 **/
  LPWSTR FileName;
} DOKAN_OPEN_INFO, *PDOKAN_OPEN_INFO;

typedef enum _DOKAN_OVERLAPPED_TYPE {

	// The overlapped operation contains a DOKAN_IO_EVENT as its payload
	DOKAN_OVERLAPPED_TYPE_IOEVENT = 0,

	// The overlapped operation payload contains a result being passed back to the
	// kernel driver. Results are represented as an EVENT_INFORMATION struct.
	DOKAN_OVERLAPPED_TYPE_IOEVENT_RESULT,

} DOKAN_OVERLAPPED_TYPE;

typedef enum _DOKAN_IO_EVENT_FLAGS {

  // There are no flags set
  DOKAN_IO_EVENT_FLAGS_NONE = 0,

  // The DOKAN_IO_EVENT object associated with the IO event
  // was allocated from a global pool and should be returned to
  // that pool instead of free'd
  DOKAN_IO_EVENT_FLAGS_POOLED = 1,

  // The EVENT_INFORMATION object associated with the IO event
  // was allocated from a global pool and should be returned to
  // that pool instead of free'd
  DOKAN_IO_EVENT_FLAGS_POOLED_RESULT = (1 << 1),

} DOKAN_IO_EVENT_FLAGS;

// See DeviceIoControl() for how InputPayload and OutputLoad are used as it's not entirely intuitive
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363216%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
typedef struct _DOKAN_OVERLAPPED {
	OVERLAPPED				InternalOverlapped;
	void					*InputPayload;
	void					*OutputPayload;
	DOKAN_OVERLAPPED_TYPE	PayloadType;
    DOKAN_IO_EVENT_FLAGS Flags;
} DOKAN_OVERLAPPED;

typedef struct _DOKAN_IO_EVENT {
  PDOKAN_INSTANCE DokanInstance;
  ULONG KernelInfoSize;
  LONG EventContextBatchSize;
  EVENT_CONTEXT EventContext[1];
} DOKAN_IO_EVENT, *PDOKAN_IO_EVENT;

typedef struct _DOKAN_CALLBACK_PARAM {
  PDOKAN_IO_EVENT IoEvent;
  PEVENT_CONTEXT EventContext;
} DOKAN_CALLBACK_PARAM, *PDOKAN_CALLBACK_PARAM;

BOOL DokanStart(PDOKAN_INSTANCE Instance);

BOOL StartDeviceIO(PDOKAN_INSTANCE Dokan, DOKAN_OVERLAPPED *Overlapped);

BOOL SendToDevice(LPCWSTR DeviceName, DWORD IoControlCode, PVOID InputBuffer,
                  ULONG InputLength, PVOID OutputBuffer, ULONG OutputLength,
                  PULONG ReturnedLength);

VOID
GetRawDeviceName(LPCWSTR DeviceName, LPWSTR DestinationBuffer,
                 rsize_t DestinationBufferSizeInElements);

void ALIGN_ALLOCATION_SIZE(PLARGE_INTEGER size, PDOKAN_OPTIONS DokanOptions);

VOID CALLBACK DokanLoop(
	_Inout_     PTP_CALLBACK_INSTANCE Instance,
	_Inout_opt_ PVOID                 Context,
	_Inout_opt_ PVOID                 Overlapped,
	_In_        ULONG                 IoResult,
	_In_        ULONG_PTR             NumberOfBytesTransferred,
	_Inout_     PTP_IO                Io
);

BOOL DokanMount(LPCWSTR MountPoint, LPCWSTR DeviceName,
                PDOKAN_OPTIONS DokanOptions);

BOOL IsMountPointDriveLetter(LPCWSTR mountPoint);

BOOL SendEventInformation(PEVENT_INFORMATION EventInfo, PDOKAN_IO_EVENT IoEvent,
                          PEVENT_CONTEXT EventContext);

ULONG DispatchGetEventInformationLength(ULONG bufferSize);

PEVENT_INFORMATION
DispatchCommon(PEVENT_CONTEXT EventContext, ULONG SizeOfEventInfo,
               PDOKAN_INSTANCE DokanInstance, PDOKAN_FILE_INFO DokanFileInfo,
               PDOKAN_OPEN_INFO *DokanOpenInfo);

VOID DispatchDirectoryInformation(PDOKAN_IO_EVENT IoEvent,
                                  PEVENT_CONTEXT EventContext);

VOID DispatchQueryInformation(PDOKAN_IO_EVENT IoEvent,
                              PEVENT_CONTEXT EventContext);

VOID DispatchQueryVolumeInformation(PDOKAN_IO_EVENT IoEvent,
                                    PEVENT_CONTEXT EventContext);

VOID DispatchSetInformation(PDOKAN_IO_EVENT IoEvent,
                            PEVENT_CONTEXT EventContext);

VOID DispatchRead(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchWrite(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchCreate(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchClose(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchCleanup(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchFlush(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchLock(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext);

VOID DispatchQuerySecurity(PDOKAN_IO_EVENT IoEvent,
                           PEVENT_CONTEXT EventContext);

VOID DispatchSetSecurity(PDOKAN_IO_EVENT IoEvent,
                         PEVENT_CONTEXT EventContext);

BOOLEAN
InstallDriver(SC_HANDLE SchSCManager, LPCWSTR DriverName, LPCWSTR ServiceExe);

BOOLEAN
RemoveDriver(SC_HANDLE SchSCManager, LPCWSTR DriverName);

BOOLEAN
StartDriver(SC_HANDLE SchSCManager, LPCWSTR DriverName);

BOOLEAN
StopDriver(SC_HANDLE SchSCManager, LPCWSTR DriverName);

BOOLEAN
ManageDriver(LPCWSTR DriverName, LPCWSTR ServiceName, USHORT Function);

BOOL SendReleaseIRP(LPCWSTR DeviceName);

BOOL SendGlobalReleaseIRP(LPCWSTR MountPoint);

VOID CheckFileName(LPWSTR FileName);

VOID ClearFindData(PLIST_ENTRY ListHead);

VOID ClearFindStreamData(PLIST_ENTRY ListHead);

PDOKAN_OPEN_INFO
GetDokanOpenInfo(PEVENT_CONTEXT EventInfomation, PDOKAN_INSTANCE DokanInstance);

VOID ReleaseDokanOpenInfo(PEVENT_INFORMATION EventInfomation,
                          PDOKAN_FILE_INFO FileInfo,
                          PDOKAN_INSTANCE DokanInstance);
                          
void ResetOverlapped(DOKAN_OVERLAPPED *overlapped);

/**
 * \brief Unmount a Dokan device from a mount point
 *
 * Same as \ref DokanRemoveMountPoint
 * If Safe is \c TRUE, it will broadcast to all desktops and Shells
 * Safe should not be used during DLL_PROCESS_DETACH
 *
 * \see DokanRemoveMountPoint
 *
 * \param MountPoint Mount point to unmount ("Z", "Z:", "Z:\", "Z:\MyMountPoint").
 * \param Safe Process is not in DLL_PROCESS_DETACH state.
 * \return \c TRUE if device was unmounted or \c FALSE in case of failure or device not found.
 */
BOOL DokanRemoveMountPointEx(LPCWSTR MountPoint, BOOL Safe);

void PushIoEventBuffer(DOKAN_IO_EVENT *IoEvent);

#ifdef __cplusplus
}
#endif

#endif // DOKANI_H_
