/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2020 Google, Inc.
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

#include "dokani.h"

#include <assert.h>


VOID SendWriteRequest(PDOKAN_IO_EVENT IoEvent,
                      PEVENT_INFORMATION EventInfo, ULONG SizeOfEventInfo,
                      ULONG WriteEventContextLength) {
  DWORD lastError = 0;
  DOKAN_OVERLAPPED *overlapped;
  DOKAN_IO_EVENT *writeIoEvent =
      malloc((SIZE_T)FIELD_OFFSET(DOKAN_IO_EVENT, EventContext) +
             WriteEventContextLength);
  if (!writeIoEvent) {
    DokanDbgPrint("Dokan Error: Failed to allocate IO event buffer.\n");
    return;
  }

  writeIoEvent->DokanInstance = IoEvent->DokanInstance;
  overlapped = malloc(sizeof(DOKAN_OVERLAPPED));
  if (!overlapped) {
    DokanDbgPrint("Dokan Error: Failed to allocate overlapped info.\n");
    free(writeIoEvent);
    return;
  }
  ResetOverlapped(overlapped);

  overlapped->OutputPayload = writeIoEvent;
  overlapped->PayloadType = DOKAN_OVERLAPPED_TYPE_IOEVENT;
  StartThreadpoolIo(IoEvent->DokanInstance->ThreadInfo.IoCompletion);
  if (!DeviceIoControl(
          IoEvent->DokanInstance->Device,   // Handle to device
          FSCTL_EVENT_WRITE,              // IO Control code
          EventInfo,                      // Input Buffer to driver.
          SizeOfEventInfo,                // Length of input buffer in bytes.
          &writeIoEvent->EventContext[0], // Output Buffer from driver.
          WriteEventContextLength,        // Length of output buffer in bytes.
          NULL,                           // Bytes placed in buffer.
          (OVERLAPPED *)overlapped        // asynchronous call
          )) {
    lastError = GetLastError();
    if (lastError != ERROR_IO_PENDING) {
      DbgPrint(
          "Dokan Error: Dokan device ioctl failed for wait with code %d.\n",
          lastError);
      CancelThreadpoolIo(IoEvent->DokanInstance->ThreadInfo.IoCompletion);
      PushIoEventBuffer(IoEvent);
      free(writeIoEvent);
      free(overlapped);
      return;
    }
  }
  DokanDbgPrint("WRITE PARTIAL SUCCESSS\n");
  PushIoEventBuffer(IoEvent);
  return;
}

VOID DispatchWrite(PDOKAN_IO_EVENT IoEvent, PEVENT_CONTEXT EventContext) {
  PEVENT_INFORMATION eventInfo;
  PDOKAN_OPEN_INFO openInfo;
  ULONG writtenLength = 0;
  NTSTATUS status;
  DOKAN_FILE_INFO fileInfo;
  ULONG sizeOfEventInfo = DispatchGetEventInformationLength(0);

  eventInfo = DispatchCommon(EventContext, sizeOfEventInfo,
                             IoEvent->DokanInstance, &fileInfo, &openInfo);

  // Since driver requested bigger memory,
  // allocate enough memory and send it to driver
  if (EventContext->Operation.Write.RequestLength > 0) {
    SendWriteRequest(IoEvent, eventInfo, sizeOfEventInfo,
                     EventContext->Operation.Write.RequestLength);
    free(eventInfo);
    return;
  }

  CheckFileName(EventContext->Operation.Write.FileName);

  DbgPrint("###WriteFile %04d\n", openInfo != NULL ? openInfo->EventId : -1);

  // for the case SendWriteRequest success
  if (IoEvent->DokanInstance->DokanOperations->WriteFile) {
    status = IoEvent->DokanInstance->DokanOperations->WriteFile(
        EventContext->Operation.Write.FileName,
        (PCHAR)EventContext + EventContext->Operation.Write.BufferOffset,
        EventContext->Operation.Write.BufferLength, &writtenLength,
        EventContext->Operation.Write.ByteOffset.QuadPart, &fileInfo);
  } else {
    status = STATUS_NOT_IMPLEMENTED;
  }

  if (openInfo != NULL)
    openInfo->UserContext = fileInfo.Context;
  eventInfo->Status = status;
  eventInfo->BufferLength = 0;

  if (status == STATUS_SUCCESS) {
    eventInfo->BufferLength = writtenLength;
    eventInfo->Operation.Write.CurrentByteOffset.QuadPart =
        EventContext->Operation.Write.ByteOffset.QuadPart + writtenLength;
  }

  ReleaseDokanOpenInfo(eventInfo, &fileInfo, IoEvent->DokanInstance);
  SendEventInformation(eventInfo, IoEvent, EventContext);
  free(eventInfo);
}
