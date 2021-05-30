#include "hv.h"
extern HV_PARTITION_ID selfPartID;

extern HV_STATUS callWinHvConnectPort(
	HV_PARTITION_ID ConnectionPartition,
	HV_CONNECTION_ID ConnectionId,
	HV_PARTITION_ID PortPartition,
	HV_PORT_ID PortId,
	HV_CONNECTION_INFO ConnectionInfo
);

UINT64 GetModuleBaseAddress(PCHAR modulename) {
	UINT64 baseaddress = 0;
	ULONG Len = 0;
	PVOID pBuffer;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;

	ZwQuerySystemInformation(SystemModuleInformation, &pSystemModuleInformation, 0, &Len);
	pBuffer = MmAllocateNonCachedMemory(Len);

	if (!pBuffer) {
		return baseaddress;
	}

	if (ZwQuerySystemInformation(SystemModuleInformation, pBuffer, Len, &Len)) {
		MmFreeNonCachedMemory(pBuffer, Len);
		return baseaddress;
	}

	UINT32 ModuleCount = *(UINT32*)pBuffer;
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)((PCHAR)pBuffer + sizeof(size_t));

	for (UINT32 i = 0; i < ModuleCount; i++) {
		if (strstr(pSystemModuleInformation->Module->ImageName, modulename)) {
			baseaddress = (UINT64)pSystemModuleInformation->Module->Base;
			break;
		}
		pSystemModuleInformation++;
	}

	MmFreeNonCachedMemory(pBuffer, Len);
	return baseaddress;
}

HV_STATUS SendGuestHostMessage(UINT32 connectionid, UINT32 messagetype) {
	HV_STATUS hvStatus = 0;
	HV_CONNECTION_ID ConnectionId = { 0 };
	HV_MESSAGE_TYPE MessageType = messagetype;

	ConnectionId.Id = connectionid;
	char message[] = "Enlighten Me!";

	hvStatus = WinHvPostMessage(ConnectionId, MessageType, &message, 14);
	return hvStatus;
}