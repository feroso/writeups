
#include "hv.h"
extern PVOID pHvlpInterruptCallbackOrig;
extern PVOID pWinHVOnInterruptOrig;
extern PVOID pXPartEnlightenedIsrOrig;
extern HV_PARTITION_ID selfPartID;
extern UINT64 GetModuleBaseAddress(PCHAR modulename);


NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp );
VOID     UnloadRoutine(IN PDRIVER_OBJECT DriverObject);
NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo, IN PIRP Irp);
NTSTATUS ReadWrite_IRPhandler(IN PDEVICE_OBJECT fdo, IN PIRP Irp);

KSPIN_LOCK MySpinLock;

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject,
                      IN PUNICODE_STRING RegistryPath  )
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT  fdo;
	UNICODE_STRING  devName;
	PEXAMPLE_DEVICE_EXTENSION dx;
	UNICODE_STRING symLinkName;

	DriverObject->DriverUnload = UnloadRoutine;
	DriverObject->MajorFunction[IRP_MJ_CREATE]= Create_File_IRPprocessing;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close_HandleIRPprocessing;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]= DeviceControlRoutine;
    DriverObject->MajorFunction[IRP_MJ_READ] = ReadWrite_IRPhandler;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = ReadWrite_IRPhandler;

	RtlInitUnicodeString( &devName, L"\\Device\\enlightenme" );

	status = IoCreateDevice(DriverObject,
                            sizeof(EXAMPLE_DEVICE_EXTENSION),
                            &devName, 
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE, 
                            &fdo);
	if(!NT_SUCCESS(status)) return status;

	dx = (PEXAMPLE_DEVICE_EXTENSION)fdo->DeviceExtension;
	dx->fdo = fdo;  

	#define   SYM_LINK_NAME   L"\\DosDevices\\enlightenme"

	RtlInitUnicodeString( &symLinkName, SYM_LINK_NAME );
	dx->ustrSymLinkName = symLinkName;
	
	status = IoCreateSymbolicLink( &symLinkName, &devName );
	if (!NT_SUCCESS(status))
	{ 
		DbgLog("Error IoCreateSymbolicLink", status);
        IoDeleteDevice( fdo );
		return status;
    } 

	InitWinHV();
	
	if (selfPartID == 1) {
		RegisterInterrupt();		
		CreateHostPort();
	}

    return status;
}

NTSTATUS CompleteIrp( PIRP Irp, NTSTATUS status, ULONG info)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return status;
}

NTSTATUS ReadWrite_IRPhandler( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
{
	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS Create_File_IRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
	return CompleteIrp(Irp, STATUS_SUCCESS, 0); 
}

NTSTATUS Close_HandleIRPprocessing(IN PDEVICE_OBJECT fdo,IN PIRP Irp)
{
	return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS DeviceControlRoutine( IN PDEVICE_OBJECT fdo, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG BytesTxd =0; 
	PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode =	IrpStack->Parameters.DeviceIoControl.IoControlCode;
	
	ULONG counter = 0;

	ULONG inBufLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outBufLength = 0;
	PCHAR inBuf, outBuf; // pointer to Input and output buffer
	
	switch(ControlCode) {
		case IOCTL_READ_BASE_ADDRESS: {
			
			if (inBufLength > 16) {
				Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			inBuf = Irp->AssociatedIrp.SystemBuffer;
			outBuf = Irp->AssociatedIrp.SystemBuffer;

			size_t modulenamelen = strlen((PCHAR)inBuf) + 1;
			if (modulenamelen != inBufLength) {
				Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			*(PUINT64)(Irp->AssociatedIrp.SystemBuffer) = GetModuleBaseAddress(inBuf);
			outBufLength = 8;
			break;
		}

		case IOCTL_WRITE_BYTE_TO_ADDRESS:
		{
			if (inBufLength != 9) {
				Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			PUINT8 pTargetAddress = *(PUINT8 *)(Irp->AssociatedIrp.SystemBuffer);
			UINT8 targetValue = *((PUINT8)(Irp->AssociatedIrp.SystemBuffer)+8);
			
			*pTargetAddress = targetValue;		
			break;
		}

		case IOCTL_READ_BYTE_FROM_ADDRESS:
		{
			if (inBufLength != 8) {
				Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			PUINT8 pTargetAddress = *(PUINT8 *)(Irp->AssociatedIrp.SystemBuffer);
			*(PUINT8)(Irp->AssociatedIrp.SystemBuffer) = *pTargetAddress;
			outBufLength = 1;
			break;
		}

		case IOCTL_HVPOSTMESSAGE:
		{
			if(inBufLength != 8) {
				Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			PHV_POSTMESSAGE_PARAMS params = (PHV_POSTMESSAGE_PARAMS)(Irp->AssociatedIrp.SystemBuffer);

			HV_STATUS hvStatus = InitWinHV();
			if (hvStatus == HV_STATUS_SUCCESS) {
				hvStatus = SendGuestHostMessage(params->connectionid, params->messagetype);
			}
			
			*(PUINT64)(Irp->AssociatedIrp.SystemBuffer) = hvStatus;
			outBufLength = 8;
			break;
		}
		
		default: status = STATUS_INVALID_DEVICE_REQUEST;
	}

	return CompleteIrp(Irp, status, outBufLength);
}


VOID UnloadRoutine(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextDevObj;
	int i;

	pNextDevObj = pDriverObject->DeviceObject;

	if ((pWinHVOnInterruptOrig!= NULL) & (pHvlpInterruptCallbackOrig!=NULL)){
		ArchmHvlRegisterInterruptCallback((UINT64)pWinHVOnInterruptOrig, (UINT64)pHvlpInterruptCallbackOrig, WIN_HV_ON_INTERRUPT_INDEX);
	}

	for(i=0; pNextDevObj!=NULL; i++)
	{
		PEXAMPLE_DEVICE_EXTENSION dx = (PEXAMPLE_DEVICE_EXTENSION)pNextDevObj->DeviceExtension;
		UNICODE_STRING *pLinkName = & (dx->ustrSymLinkName);
		pNextDevObj = pNextDevObj->NextDevice;
		IoDeleteSymbolicLink(pLinkName);
		IoDeleteDevice(dx->fdo);
	}
}