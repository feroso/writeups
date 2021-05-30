#include "hv.h"
#include "distorm\src\decoder.h"


PVOID pWinHVOnInterruptOrig = NULL;
PVOID (*pWinHvpConnectToHypervisor)() = NULL;
PVOID pXPartEnlightenedIsrOrig = NULL;
PVOID pHvlpInterruptCallbackOrig = NULL;
PVOID pSIMP[MAX_PROCESSOR_COUNT];
PVOID pSIEFP[MAX_PROCESSOR_COUNT];
PHV_MESSAGE hvMessage = NULL;
HV_PARTITION_ID selfPartID = HV_PARTITION_ID_SELF;
PUINT8 pWinHvpRunningLoopback = NULL;
//CHAR flag0[] = "CTF-BR{REDAC";
//CHAR flag1[] = "TED1REDACTED";
//CHAR flag2[] = "1REDACTED1RE";
//CHAR flag3[] = "DACTED1REDAC";
//CHAR flag4[] = "TED1REDACTE}";
//CHAR flag0[] = "CTF-BR{!!Gu3";
//CHAR flag1[] = "Ss_7he_4nswe";
//CHAR flag2[] = "r_Was_Never_";
//CHAR flag3[] = "Me4nt_70_be_";
//CHAR flag4[] = "F0und!!!!!!}";
CHAR flag0[] = "CTF-BR{!Wh3n";
CHAR flag1[] = "_7he_5earcH_";
CHAR flag2[] = "1s_Ov3r_Our_";
CHAR flag3[] = "Qu3st1ons_5t";
CHAR flag4[] = "ill_Remain!}";
CHAR emulatedmanufacturer0[] = "bhyve bhyve ";
CHAR emulatedmanufacturer1[] = " KVMKVMKVM  ";
CHAR emulatedmanufacturer2[] = "TCGTCGTCGTCG";
CHAR emulatedmanufacturer3[] = "Microsoft Hv";
CHAR emulatedmanufacturer4[] = " lrpepyh vr ";
CHAR emulatedmanufacturer5[] = "VMwareVMware";
CHAR emulatedmanufacturer6[] = "XenVMMXenVMM";
CHAR emulatedmanufacturer7[] = "ACRNACRNACRN";
CHAR emulatedmanufacturer8[] = " QNXQVMBSQG ";
CHAR emulatedmanufacturer9[] = "VirtualApple";
CHAR emulatedmanufacturer10[] = "GenuineIntel";

HV_STATUS InitWinHV() {
	HV_PARTITION_ID PartID;
	HV_STATUS hvStatus = WinHvGetPartitionId(&PartID);
	
	if (hvStatus == HV_STATUS_SUCCESS) {
		selfPartID = PartID;
	}
	
	return hvStatus;
}

int SetupInterception()
{
	HV_STATUS hvStatus = 0;
	HV_PARTITION_ID NextPartID = HV_PARTITION_ID_INVALID;
	HV_INTERCEPT_DESCRIPTOR CpuidDescriptor;
	HV_INTERCEPT_PARAMETERS CpuidParameters = { 0 };
	
	do
	{
		hvStatus = WinHvGetNextChildPartition(selfPartID, NextPartID, &NextPartID);
		if (NextPartID != 0) {
			CpuidParameters.CpuidIndex = 0x40000100;
			CpuidDescriptor.Type = HvInterceptTypeX64Cpuid;
			CpuidDescriptor.Parameters = CpuidParameters;
			hvStatus = WinHvInstallIntercept(NextPartID, HV_INTERCEPT_ACCESS_MASK_EXECUTE, &CpuidDescriptor);
		}
	} while ((NextPartID != HV_PARTITION_ID_INVALID));
	return 0;
}

int FindHvlpInterruptCallback(unsigned char* buf)
{
	_DecodeResult res;
	_DInst adv_res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0, i, next;
	_DecodeType dt = Decode64Bits;
	const char* sMnemonicName = "LEA";
	const char* sOperandName = "R10";
	_CodeInfo ci;

	_OffsetType offset = 0;
	char* errch = NULL;

	int len = 100;
	for (;;) {
		res = distorm_decode64(offset, (const unsigned char*)buf, len, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR) {			
			break;
		}
		for (i = 0; i < decodedInstructionsCount; i++) {
			if (strstr((char*)decodedInstructions[i].mnemonic.p, (char*)sMnemonicName) && strstr((char*)decodedInstructions[i].operands.p, (char*)sOperandName)) {
				ci.codeOffset = offset;
				ci.code = (const unsigned char*)buf;
				ci.codeLen = len;
				ci.dt = dt;
				ci.features = DF_NONE;
				res = decode_internal(&ci, FALSE, &adv_res, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		
				pHvlpInterruptCallbackOrig = (PVOID)((size_t)(buf + adv_res.disp + adv_res.size));
				pWinHVOnInterruptOrig = (PVOID) * (PULONG_PTR)pHvlpInterruptCallbackOrig;
				pXPartEnlightenedIsrOrig = (PVOID) * ((PUINT64)pHvlpInterruptCallbackOrig + 1);				
				return 0;
			}
		}

		if (res == DECRES_SUCCESS || decodedInstructionsCount == 0) {
			break; // All instructions were decoded.
		}

		// Synchronize:
		next = (unsigned int)(decodedInstructions[decodedInstructionsCount - 1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount - 1].size;

		// Advance ptr and recalc offset.
		buf += next;
		len -= next;
		offset += next;
	}
	return 1;
}

int RegisterInterrupt()
{
	UNICODE_STRING     uniName;
	PVOID pvHvlRegisterAddress = NULL;
	PHYSICAL_ADDRESS pAdr = { 0 };
	ULONG i, ProcessorCount;
	ProcessorCount = KeQueryActiveProcessorCount(NULL);

	RtlInitUnicodeString(&uniName, L"HvlRegisterInterruptCallback");
	pvHvlRegisterAddress = MmGetSystemRoutineAddress(&uniName);
	
	if (pvHvlRegisterAddress == NULL) {
		return 0;
	}
	
	FindHvlpInterruptCallback((unsigned char*)pvHvlRegisterAddress);
	
	for (i = 0; i < ProcessorCount; i++) {
		KeSetSystemAffinityThreadEx(1i64 << i);
		
		pAdr.QuadPart = ArchReadMsr(HV_X64_MSR_SIMP) & 0xFFFFFFFFFFFFF000;
		pSIMP[i] = MmMapIoSpace(pAdr, PAGE_SIZE, MmCached);
		
		if (pSIMP[i] == NULL) {			
			return 1;
		}
		
		pAdr.QuadPart = ArchReadMsr(HV_X64_MSR_SIEFP) & 0xFFFFFFFFFFFFF000;
		pSIEFP[i] = MmMapIoSpace(pAdr, PAGE_SIZE, MmCached);

		if (pSIMP[i] == NULL) {			
			return 1;
		}		
	}

	ArchmHvlRegisterInterruptCallback((UINT64)&ArchmWinHvOnInterrupt, (UINT64)pHvlpInterruptCallbackOrig, WIN_HV_ON_INTERRUPT_INDEX);
	return 0;
}

void EmulateCPUIDManufacturer()
{
	PHV_X64_CPUID_INTERCEPT_MESSAGE phvCPUID = (PHV_X64_CPUID_INTERCEPT_MESSAGE)hvMessage->Payload;
	
	if (phvCPUID->Rax == 0x40000100) {
		phvCPUID->DefaultResultRbx = *((PUINT32)emulatedmanufacturer0 + (phvCPUID->Rcx * 4)) & 0xFFFFFFFF;
		phvCPUID->DefaultResultRcx = *(((PUINT32)emulatedmanufacturer0 + (phvCPUID->Rcx * 4) + 1)) & 0xFFFFFFFF;
		phvCPUID->DefaultResultRdx = *(((PUINT32)emulatedmanufacturer0 + (phvCPUID->Rcx * 4) + 2)) & 0xFFFFFFFF;
	}
}

void ParseHvMessage()
{
	ULONG uCurProcNum = KeGetCurrentProcessorNumberEx(NULL);
	HV_MESSAGE hvMessageSINT0 = { 0 };
	HV_MESSAGE hvMessageSINT1 = { 0 };
	
	if (pSIMP[uCurProcNum] != NULL) {
		hvMessage = (PHV_MESSAGE)pSIMP[uCurProcNum];
	} 
	
	if ((PUINT8)pSIMP[uCurProcNum] + HV_MESSAGE_SIZE != NULL) {
		memcpy(&hvMessageSINT1, (PUINT8)pSIMP[uCurProcNum] + HV_MESSAGE_SIZE, HV_MESSAGE_SIZE);
	} else {
		return;
	}

	if(hvMessage->Header.MessageType != HvMessageTypeNone)
		switch (hvMessage->Header.MessageType) {
			case HvMessageTypeX64CpuidIntercept:
				EmulateCPUIDManufacturer();
				return;
			default:
				break;
		}
	
	if (hvMessageSINT1.Header.MessageType != HvMessageTypeNone)
		switch (hvMessageSINT1.Header.MessageType) {
			case HvEnlightenMeMessage:
				SetupInterception();
				return;
			default:
				break;
	}
}

HV_STATUS callWinHvCreatePort(
	UINT64 PortPartition,
	HV_PORT_ID PortId,
	UINT64 ConnectionPartition,
	HV_PORT_INFO PortInfo
) {
	return WinHvCreatePort(PortPartition, 0, PortId, ConnectionPartition, &PortInfo, 0, 0);
}

HV_STATUS callWinHvConnectPort(
	HV_PARTITION_ID ConnectionPartition,
	HV_CONNECTION_ID ConnectionId,
	HV_PARTITION_ID PortPartition,
	HV_PORT_ID PortId,
	HV_CONNECTION_INFO ConnectionInfo
) {
	return WinHvConnectPort(ConnectionPartition, 0, ConnectionId, PortPartition, PortId, &ConnectionInfo, 0);
}

HV_STATUS CreateHostPort() {
	HV_STATUS hvStatus = 0;
	HV_PORT_ID PortId = { 0 };
	HV_PORT_INFO PortInfo = { 0 };
	HV_CONNECTION_ID ConnectionId = { 0 };
	HV_CONNECTION_INFO ConnectionInfo = { 0 };
	HV_PARTITION_PROPERTY HvProp = 0;
	HV_PARTITION_PRIVILEGE_MASK * guestPrivileges = 0;
	HV_PARTITION_ID NextGuestPartID = HV_PARTITION_ID_INVALID;

	PortId.Id = 0x41414141;
	PortInfo.PortType = HvPortTypeMessage;
	PortInfo.MessagePortInfo.TargetSint = 1;
	PortInfo.MessagePortInfo.TargetVp = HV_ANY_VP;
	ConnectionId.Id = 0x42424242;
	ConnectionInfo.PortType = HvPortTypeMessage;
	
	hvStatus = WinHvGetNextChildPartition(selfPartID, HV_PARTITION_ID_INVALID, &NextGuestPartID);

	while ((NextGuestPartID != HV_PARTITION_ID_INVALID) && (hvStatus == 0)) {

		hvStatus = WinHvGetPartitionProperty(NextGuestPartID, HvPartitionPropertyPrivilegeFlags, &HvProp);
		guestPrivileges = (PHV_PARTITION_PRIVILEGE_MASK)&HvProp;

		guestPrivileges->AccessPartitionId = 1;
		hvStatus = WinHvSetPartitionProperty(NextGuestPartID, HvPartitionPropertyPrivilegeFlags, HvProp);
		hvStatus = callWinHvCreatePort(selfPartID, PortId, NextGuestPartID, PortInfo);
		hvStatus = callWinHvConnectPort(NextGuestPartID, ConnectionId, selfPartID, PortId, ConnectionInfo);
		hvStatus = WinHvGetNextChildPartition(selfPartID, NextGuestPartID, &NextGuestPartID);
	}

	return hvStatus;
}