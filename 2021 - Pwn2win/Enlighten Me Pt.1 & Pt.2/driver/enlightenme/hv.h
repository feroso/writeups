#include "Driver.h"
#include "mWin.h"
#include "distorm/include/distorm.h" 

//#define IS_GUEST

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define HV_PARTITION_ID_INVALID	0x0000000000000000UI64
#define HV_PARTITION_ID_SELF ((HV_PARTITION_ID) -1)
#define HV_STATUS_SUCCESS  0x0000	
#define HV_STATUS_INVALID_HYPERCALL_CODE  0x0002	
#define HV_STATUS_INVALID_HYPERCALL_INPUT  0x0003	
#define HV_STATUS_INVALID_ALIGNMENT  0x0004	
#define HV_STATUS_INVALID_PARAMETER  0x0005	
#define HV_STATUS_ACCESS_DENIED  0x0006	
#define HV_STATUS_INVALID_PARTITION_STATE  0x0007	
#define HV_STATUS_OPERATION_DENIED  0x0008	
#define HV_STATUS_UNKNOWN_PROPERTY  0x0009	
#define HV_STATUS_PROPERTY_VALUE_OUT_OF_RANGE  0x000A	
#define HV_STATUS_INSUFFICIENT_MEMORY  0x000B	
#define HV_STATUS_PARTITION_TOO_DEEP  0x000C	
#define HV_STATUS_INVALID_PARTITION_ID  0x000D	
#define HV_STATUS_INVALID_VP_INDEX  0x000E
#define HV_STATUS_INVALID_PORT_ID 0x0011
#define HV_STATUS_INVALID_CONNECTION_ID 0x0012

#define HV_INTERCEPT_ACCESS_MASK_NONE	0
#define HV_INTERCEPT_ACCESS_MASK_READ	1
#define HV_INTERCEPT_ACCESS_MASK_WRITE	2
#define HV_INTERCEPT_ACCESS_MASK_EXECUTE	4
#define WIN_HV_ON_INTERRUPT_OFFSET	0x1AE0 //Warning!! Hardcode constant
#define HV_SYNIC_SINT_COUNT 	16

#define HV_X64_MSR_SIMP 0x40000083
#define HV_X64_MSR_SIEFP 0x40000082
#define HV_X64_MSR_EOM 0x40000084
#define HV_X64_MSR_SINT0 0x40000090

#define MAX_PROCESSOR_COUNT 32

#define WIN_HV_ON_INTERRUPT_INDEX		0
#define XPART_ENLIGHTENED_ISR0_INDEX    1
#define XPART_ENLIGHTENED_ISR1_INDEX    2
#define XPART_ENLIGHTENED_ISR2_INDEX    3
#define XPART_ENLIGHTENED_ISR3_INDEX    4

typedef UINT64 HV_STATUS;
typedef UINT64 HV_PARTITION_ID;
typedef UINT64 HV_GPA;
typedef UINT64 HV_ADDRESS_SPACE_ID; 
typedef HV_PARTITION_ID *PHV_PARTITION_ID;
typedef UINT64 HV_NANO100_TIME;
typedef HV_NANO100_TIME *PHV_NANO100_TIME;
typedef UINT64 HV_PARTITION_PROPERTY;
typedef HV_PARTITION_PROPERTY *PHV_PARTITION_PROPERTY;
typedef UINT8 HV_INTERCEPT_ACCESS_TYPE_MASK;
typedef UINT32 HV_VP_INDEX;

HV_STATUS InitWinHV(VOID);
int SetupInterception(VOID);
int RegisterInterrupt(VOID);
int FindWinHvOnInterrupt(VOID);
VOID ParseHvMessage(VOID);
HV_STATUS CreateHostPort(VOID);
HV_STATUS SendGuestHostMessage(UINT32 connectionid, UINT32 messagetype);


typedef enum
{
	HvUnsupportedFeatureIntercept		= 1,
	HvUnsupportedFeatureTaskSwitchTss			= 2	
} HV_UNSUPPORTED_FEATURE_CODE;


typedef enum  { 
  HvPartitionPropertyPrivilegeFlags          = 0x00010000,
  HvPartitionPropertyCpuReserve              = 0x00020001,
  HvPartitionPropertyCpuCap                  = 0x00020002,
  HvPartitionPropertyCpuWeight               = 0x00020003,
  HvPartitionPropertyEmulatedTimerPeriod     = 0x00030000,
  HvPartitionPropertyEmulatedTimerControl    = 0x00030001,
  HvPartitionPropertyPmTimerAssist           = 0x00030002,
  HvPartitionPropertyDebugChannelId          = 0x00040000,
  HvPartitionPropertyVirtualTlbPageCount     = 0x00050000,
  HvPartitionPropertyProcessorVendor         = 0x00060000,
  HvPartitionPropertyProcessorFeatures       = 0x00060001,
  HvPartitionPropertyProcessorXsaveFeatures  = 0x00060002,
  HvPartitionPropertyProcessorCLFlushSize    = 0x00060003
} HV_PARTITION_PROPERTY_CODE, *PHV_PARTITION_PROPERTY_CODE;

typedef UINT16 HV_X64_IO_PORT;

typedef enum _HV_INTERCEPT_TYPE { 
  HvInterceptTypeX64IoPort     = 0x00000000,
  HvInterceptTypeX64Msr        = 0x00000001,
  HvInterceptTypeX64Cpuid      = 0x00000002,
  HvInterceptTypeX64Exception  = 0x00000003
} HV_INTERCEPT_TYPE, *PHV_INTERCEPT_TYPE;

typedef union _HV_INTERCEPT_PARAMETERS {
  UINT64         AsUINT64;
  HV_X64_IO_PORT IoPort;
  UINT32         CpuidIndex;
  UINT16         ExceptionVector;
} HV_INTERCEPT_PARAMETERS, *PHV_INTERCEPT_PARAMETERS;


typedef struct _HV_INTERCEPT_DESCRIPTOR {
  HV_INTERCEPT_TYPE       Type;
  HV_INTERCEPT_PARAMETERS Parameters;
} HV_INTERCEPT_DESCRIPTOR, *PHV_INTERCEPT_DESCRIPTOR;



typedef enum _HV_MESSAGE_TYPE { 
  HvMessageTypeNone                    = 0x00000000,
  HvEnlightenMeMessage           = 0x43434343,
  HvMessageTypeUnmappedGpa             = 0x80000000,
  HvMessageTypeGpaIntercept            = 0x80000001,
  HvMessageTimerExpired                = 0x80000010,
  HvMessageTypeInvalidVpRegisterValue  = 0x80000020,
  HvMessageTypeUnrecoverableException  = 0x80000021,
  HvMessageTypeUnsupportedFeature      = 0x80000022,
  HvMessageTypeEventLogBufferComplete  = 0x80000040,
  HvMessageTypeX64IoPortIntercept      = 0x80010000,
  HvMessageTypeX64MsrIntercept         = 0x80010001,
  HvMessageTypeX64CpuidIntercept       = 0x80010002,
  HvMessageTypeX64ExceptionIntercept   = 0x80010003,
  HvMessageTypeX64ApicEoi              = 0x80010004,
  HvMessageTypeX64LegacyFpError        = 0x80010005
} HV_MESSAGE_TYPE, *PHV_MESSAGE_TYPE;


typedef union
{
	UINT32 AsUint32;
	struct
	{
	    UINT32 Id:24;
	    UINT32 Reserved:8;
	};
} HV_CONNECTION_ID;

typedef union
{
	UINT32 AsUint32;
	struct
	{
	    UINT32 Id:24;
	    UINT32 Reserved:8;
	};
} HV_PORT_ID, * PHV_PORT_ID;

typedef enum _HV_PORT_TYPE { 
  HvPortTypeMessage  = 1,
  HvPortTypeEvent    = 2,
  HvPortTypeMonitor  = 3
} HV_PORT_TYPE, *PHV_PORT_TYPE;


typedef struct _HV_CONNECTION_INFO {
  HV_PORT_TYPE PortType;
  UINT32       Padding;
  union {
    struct {
      UINT64 RsvdZ;
    } MessageConnectionInfo;
    struct {
      UINT64 RsvdZ;
    } EventConnectionInfo;
    struct {
      HV_GPA MonitorAddress;
    } MonitorConnectionInfo;
  };
} HV_CONNECTION_INFO, *PHV_CONNECTION_INFO;

typedef UINT32 HV_SYNIC_SINT_INDEX;
typedef struct { 
	HV_PORT_TYPE PortType; 
	UINT32 ReservedZ; 
	union { 
		struct { 
			HV_SYNIC_SINT_INDEX TargetSint; 
			HV_VP_INDEX TargetVp; 
			UINT64 ReservedZ; 
		} MessagePortInfo; 
		struct { 
			HV_SYNIC_SINT_INDEX TargetSint; 
			HV_VP_INDEX TargetVp; 
			UINT16 BaseFlagNumber; 
			UINT16 FlagCount; 
			UINT32 ReservedZ; 
		} EventPortInfo; 
		struct { 
			HV_GPA MonitorAddress; 
			UINT64 ReservedZ; 
		} MonitorPortInfo; 
	}; 
} HV_PORT_INFO, * PHV_PORT_INFO;

#define HV_MESSAGE_SIZE  	256
#define HV_MESSAGE_MAX_PAYLOAD_BYTE_COUNT	240
#define HV_MESSAGE_MAX_PAYLOAD_QWORD_COUNT	30

typedef struct
{
	UINT8 MessagePending:1;
	UINT8 Reserved:7;
} HV_MESSAGE_FLAGS;


typedef struct
{
	HV_MESSAGE_TYPE	MessageType; 
	UINT16	Reserved; 
	HV_MESSAGE_FLAGS	MessageFlags; 
	UINT8	PayloadSize; 
	union 
	{
        UINT64		OriginationId;
		HV_PARTITION_ID		Sender;
		HV_PORT_ID		Port;
	};
} HV_MESSAGE_HEADER;

typedef struct
{
	HV_MESSAGE_HEADER	Header;
	UINT64	Payload[HV_MESSAGE_MAX_PAYLOAD_QWORD_COUNT];
} HV_MESSAGE, *PHV_MESSAGE;

typedef union _HV_X64_IO_PORT_ACCESS_INFO {
  UINT8  AsUINT8;
  struct {
    UINT8 AccessSize  :3;
    UINT8 StringOp  :1;
    UINT8 RepPrefix  :1;
    UINT8 Reserved  :3;
  };
} HV_X64_IO_PORT_ACCESS_INFO, *PHV_X64_IO_PORT_ACCESS_INFO;

typedef union _HV_X64_VP_EXECUTION_STATE {
  UINT16 AsUINT16;
  struct {
    UINT16 Cpl  :2;
    UINT16 Cr0Pe  :1;
    UINT16 Cr0Am  :1;
    UINT16 EferLma  :1;
    UINT16 DebugActive  :1;
    UINT16 InterruptionPending  :1;
    UINT16 Reserved  :9;
  };
} HV_X64_VP_EXECUTION_STATE, *PHV_X64_VP_EXECUTION_STATE;

typedef struct _HV_X64_SEGMENT_REGISTER {
  UINT64 Base;
  UINT32 Limit;
  UINT16 Selector;
  union {
    struct {
      UINT16 SegmentType  :4;
      UINT16 NonSystemSegment  :1;
      UINT16 DescriptorPrivilegeLevel  :2;
      UINT16 Present  :1;
      UINT16 Reserved  :4;
      UINT16 Available  :1;
      UINT16 Long  :1;
      UINT16 Default  :1;
      UINT16 Granularity  :1;
    };
    UINT16 Attributes;
  };
} HV_X64_SEGMENT_REGISTER, *PHV_X64_SEGMENT_REGISTER;


typedef struct _HV_X64_INTERCEPT_MESSAGE_HEADER {
  HV_VP_INDEX               VpIndex;
  UINT8                     InstructionLength;
  HV_INTERCEPT_ACCESS_TYPE_MASK  InterceptAccessType;//in original undefined type HV_INTERCEPT_ACCESS_TYPE - A bitwise OR combination of HV_INTERCEPT_ACCESS_TYPE_MASK 
  HV_X64_VP_EXECUTION_STATE ExecutionState;
  HV_X64_SEGMENT_REGISTER   CsSegment;
  UINT64                    Rip;
  UINT64                    Rflags;
} HV_X64_INTERCEPT_MESSAGE_HEADER, *PHV_X64_INTERCEPT_MESSAGE_HEADER;


typedef struct _HV_X64_IO_PORT_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT16                          PortNumber;
  HV_X64_IO_PORT_ACCESS_INFO      AccessInfo;
  UINT8                           InstructionByteCount;
  UINT32                          Reserved;
  UINT64                          Rax;
  //UINT64                          InstructionBytes0;
  //UINT64                          InstructionBytes1;
  UINT8                           InstructionBytes[16];
  HV_X64_SEGMENT_REGISTER         DsSegment;
  HV_X64_SEGMENT_REGISTER         EsSegment;
  UINT64                          Rcx;
  UINT64                          Rsi;
  UINT64                          Rdi;
} HV_X64_IO_PORT_INTERCEPT_MESSAGE, *PHV_X64_IO_PORT_INTERCEPT_MESSAGE;


typedef struct _HV_X64_CPUID_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT64                          Rax;
  UINT64                          Rcx;
  UINT64                          Rdx;
  UINT64                          Rbx;
  UINT64                          DefaultResultRax;
  UINT64                          DefaultResultRcx;
  UINT64                          DefaultResultRdx;
  UINT64                          DefaultResultRbx;
} HV_X64_CPUID_INTERCEPT_MESSAGE, *PHV_X64_CPUID_INTERCEPT_MESSAGE;

typedef struct _HV_X64_MSR_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT32                          MsrNumber;
  UINT32                          Reserved;
  UINT64                          Rdx;
  UINT64                          Rax;
} HV_X64_MSR_INTERCEPT_MESSAGE, *PHV_X64_MSR_INTERCEPT_MESSAGE;

typedef union _HV_X64_EXCEPTION_INFO {
  UINT8  AsUINT8;
  struct {
    UINT8 ErrorCodeValid  :1;
    UINT8 Reserved  :7;
  };
} HV_X64_EXCEPTION_INFO, *PHV_X64_EXCEPTION_INFO;


typedef struct _HV_X64_EXCEPTION_INTERCEPT_MESSAGE {
  HV_X64_INTERCEPT_MESSAGE_HEADER Header;
  UINT16                          ExceptionVector;
  HV_X64_EXCEPTION_INFO           ExceptionInfo;
  UINT8                           InstructionByteCount;
  UINT32                          ErrorCode;
  UINT64                          ExceptionParameter;
  UINT64                          Reserved;
  UINT8                           InstructionBytes[16];
  HV_X64_SEGMENT_REGISTER         DsSegment;
  HV_X64_SEGMENT_REGISTER         SsSegment;
  UINT64                          Rax;
  UINT64                          Rcx;
  UINT64                          Rdx;
  UINT64                          Rbx;
  UINT64                          Rsp;
  UINT64                          Rbp;
  UINT64                          Rsi;
  UINT64                          Rdi;
  UINT64                          R8;
  UINT64                          R9;
  UINT64                          R10;
  UINT64                          R11;
  UINT64                          R12;
  UINT64                          R13;
  UINT64                          R14;
  UINT64                          R15;
} HV_X64_EXCEPTION_INTERCEPT_MESSAGE, *PHV_X64_EXCEPTION_INTERCEPT_MESSAGE;

typedef enum {
	// Suspend Registers
	HvRegisterExplicitSuspend = 0x00000000,
	HvRegisterInterceptSuspend = 0x00000001,
	// Version 
	// 128-bit result same as CPUID 0x40000002 
	HvRegisterHypervisorVersion = 0x00000100,
	// Feature Access (registers are 128 bits) 
	// 128-bit result same as CPUID 0x40000003 
	HvRegisterPrivilegesAndFeaturesInfo = 0x00000200,
	// 128-bit result same as CPUID 0x40000004 
	HvRegisterFeaturesInfo = 0x00000201,
	// 128-bit result same as CPUID 0x40000005 
	HvRegisterImplementationLimitsInfo = 0x00000202,
	// 128-bit result same as CPUID 0x40000006 
	HvRegisterHardwareFeaturesInfo = 0x00000203,
	// Guest Crash Registers 
	HvRegisterGuestCrashP0 = 0x00000210,
	HvRegisterGuestCrashP1 = 0x00000211,
	HvRegisterGuestCrashP2 = 0x00000212,
	HvRegisterGuestCrashP3 = 0x00000213,
	HvRegisterGuestCrashP4 = 0x00000214,
	HvRegisterGuestCrashCtl = 0x00000215,
	// Power State Configuration 
	HvRegisterPowerStateConfigC1 = 0x00000220,
	HvRegisterPowerStateTriggerC1 = 0x00000221,
	HvRegisterPowerStateConfigC2 = 0x00000222,
	HvRegisterPowerStateTriggerC2 = 0x00000223,
	HvRegisterPowerStateConfigC3 = 0x00000224,
	HvRegisterPowerStateTriggerC3 = 0x00000225,
	// Frequency Registers 
	HvRegisterProcessorClockFrequency = 0x00000240,
	HvRegisterInterruptClockFrequency = 0x00000241,
	// Idle Register 
	HvRegisterGuestIdle = 0x00000250,
	// Guest Debug 
	HvRegisterDebugDeviceOptions = 0x00000260,
	// Pending Interruption Register 
	HvRegisterPendingInterruption = 0x00010002,
	// Interrupt State register 
	HvRegisterInterruptState = 0x00010003,
	// Pending Event Register 
	HvRegisterPendingEvent0 = 0x00010004,
	HvRegisterPendingEvent1 = 0x00010005,
	// User-Mode Registers 
	HvX64RegisterRax = 0x00020000,
	HvX64RegisterRcx = 0x00020001,
	HvX64RegisterRdx = 0x00020002,
	HvX64RegisterRbx = 0x00020003,
	HvX64RegisterRsp = 0x00020004,
	HvX64RegisterRbp = 0x00020005,
	HvX64RegisterRsi = 0x00020006,
	HvX64RegisterRdi = 0x00020007,
	HvX64RegisterR8 = 0x00020008,
	HvX64RegisterR9 = 0x00020009,
	HvX64RegisterR10 = 0x0002000A,
	HvX64RegisterR11 = 0x0002000B,
	HvX64RegisterR12 = 0x0002000C,
	HvX64RegisterR13 = 0x0002000D,
	HvX64RegisterR14 = 0x0002000E,
	HvX64RegisterR15 = 0x0002000F,
	HvX64RegisterRip = 0x00020010,
	HvX64RegisterRflags = 0x00020011,
	// Floating Point and Vector Registers 
	HvX64RegisterXmm0 = 0x00030000,
	HvX64RegisterXmm1 = 0x00030001,
	HvX64RegisterXmm2 = 0x00030002,
	HvX64RegisterXmm3 = 0x00030003,
	HvX64RegisterXmm4 = 0x00030004,
	HvX64RegisterXmm5 = 0x00030005,
	HvX64RegisterXmm6 = 0x00030006,
	HvX64RegisterXmm7 = 0x00030007,
	HvX64RegisterXmm8 = 0x00030008,
	HvX64RegisterXmm9 = 0x00030009,
	HvX64RegisterXmm10 = 0x0003000A,
	HvX64RegisterXmm11 = 0x0003000B,
	HvX64RegisterXmm12 = 0x0003000C,
	HvX64RegisterXmm13 = 0x0003000D,
	HvX64RegisterXmm14 = 0x0003000E,
	HvX64RegisterXmm15 = 0x0003000F,
	HvX64RegisterFpMmx0 = 0x00030010,
	HvX64RegisterFpMmx1 = 0x00030011,
	HvX64RegisterFpMmx2 = 0x00030012,
	HvX64RegisterFpMmx3 = 0x00030013,
	HvX64RegisterFpMmx4 = 0x00030014,
	HvX64RegisterFpMmx5 = 0x00030015,
	HvX64RegisterFpMmx6 = 0x00030016,
	HvX64RegisterFpMmx7 = 0x00030017,
	HvX64RegisterFpControlStatus = 0x00030018,
	HvX64RegisterXmmControlStatus = 0x00030019,
	// Control Registers 
	HvX64RegisterCr0 = 0x00040000,
	HvX64RegisterCr2 = 0x00040001,
	HvX64RegisterCr3 = 0x00040002,
	HvX64RegisterCr4 = 0x00040003,
	HvX64RegisterCr8 = 0x00040004,
	HvX64RegisterXfem = 0x00040005,
	// X64 Intermediate Control Registers 
	HvX64RegisterIntermediateCr0 = 0x00041000,
	HvX64RegisterIntermediateCr4 = 0x00041003,
	HvX64RegisterIntermediateCr8 = 0x00041004,
	// Debug Registers 
	HvX64RegisterDr0 = 0x00050000,
	HvX64RegisterDr1 = 0x00050001,
	HvX64RegisterDr2 = 0x00050002,
	HvX64RegisterDr3 = 0x00050003,
	HvX64RegisterDr6 = 0x00050004,
	HvX64RegisterDr7 = 0x00050005,
	// Segment Registers
	HvX64RegisterEs = 0x00060000,
	HvX64RegisterCs = 0x00060001,
	HvX64RegisterSs = 0x00060002,
	HvX64RegisterDs = 0x00060003,
	HvX64RegisterFs = 0x00060004,
	HvX64RegisterGs = 0x00060005,
	HvX64RegisterLdtr = 0x00060006,
	HvX64RegisterTr = 0x00060007,
	// Table Registers 
	HvX64RegisterIdtr = 0x00070000,
	HvX64RegisterGdtr = 0x00070001,
	// Virtualized MSRs 
	HvX64RegisterTsc = 0x00080000,
	HvX64RegisterEfer = 0x00080001,
	HvX64RegisterKernelGsBase = 0x00080002,
	HvX64RegisterApicBase = 0x00080003,
	HvX64RegisterPat = 0x00080004,
	HvX64RegisterSysenterCs = 0x00080005,
	HvX64RegisterSysenterRip = 0x00080006,
	HvX64RegisterSysenterRsp = 0x00080007,
	HvX64RegisterStar = 0x00080008,
	HvX64RegisterLstar = 0x00080009,
	HvX64RegisterCstar = 0x0008000A,
	HvX64RegisterSfmask = 0x0008000B,
	HvX64RegisterInitialApicId = 0x0008000C,
	// Cache control MSRs 
	HvX64RegisterMtrrCap = 0x0008000D,
	HvX64RegisterMtrrDefType = 0x0008000E,
	HvX64RegisterMtrrPhysBase0 = 0x00080010,
	HvX64RegisterMtrrPhysBase1 = 0x00080011,
	HvX64RegisterMtrrPhysBase2 = 0x00080012,
	HvX64RegisterMtrrPhysBase3 = 0x00080013,
	HvX64RegisterMtrrPhysBase4 = 0x00080014,
	HvX64RegisterMtrrPhysBase5 = 0x00080015,
	HvX64RegisterMtrrPhysBase6 = 0x00080016,
	HvX64RegisterMtrrPhysBase7 = 0x00080017,
	HvX64RegisterMtrrPhysBase8 = 0x00080018,
	HvX64RegisterMtrrPhysBase9 = 0x00080019,
	HvX64RegisterMtrrPhysBaseA = 0x0008001A,
	HvX64RegisterMtrrPhysBaseB = 0x0008001B,
	HvX64RegisterMtrrPhysBaseC = 0x0008001C,
	HvX64RegisterMtrrPhysBaseD = 0x0008001D,
	HvX64RegisterMtrrPhysBaseE = 0x0008001E,
	HvX64RegisterMtrrPhysBaseF = 0x0008001F,
	HvX64RegisterMtrrPhysMask0 = 0x00080040,
	HvX64RegisterMtrrPhysMask1 = 0x00080041,
	HvX64RegisterMtrrPhysMask2 = 0x00080042,
	HvX64RegisterMtrrPhysMask3 = 0x00080043,
	HvX64RegisterMtrrPhysMask4 = 0x00080044,
	HvX64RegisterMtrrPhysMask5 = 0x00080045,
	HvX64RegisterMtrrPhysMask6 = 0x00080046,
	HvX64RegisterMtrrPhysMask7 = 0x00080047,
	HvX64RegisterMtrrPhysMask8 = 0x00080048,
	HvX64RegisterMtrrPhysMask9 = 0x00080049,
	HvX64RegisterMtrrPhysMaskA = 0x0008004A,
	HvX64RegisterMtrrPhysMaskB = 0x0008004B,
	HvX64RegisterMtrrPhysMaskC = 0x0008004C,
	HvX64RegisterMtrrPhysMaskD = 0x0008004D,
	HvX64RegisterMtrrPhysMaskE = 0x0008004E,
	HvX64RegisterMtrrPhysMaskF = 0x0008004F,
	HvX64RegisterMtrrFix64k00000 = 0x00080070,
	HvX64RegisterMtrrFix16k80000 = 0x00080071,
	HvX64RegisterMtrrFix16kA0000 = 0x00080072,
	HvX64RegisterMtrrFix4kC0000 = 0x00080073,
	HvX64RegisterMtrrFix4kC8000 = 0x00080074,
	HvX64RegisterMtrrFix4kD0000 = 0x00080075,
	HvX64RegisterMtrrFix4kD8000 = 0x00080076,
	HvX64RegisterMtrrFix4kE0000 = 0x00080077,
	HvX64RegisterMtrrFix4kE8000 = 0x00080078,
	HvX64RegisterMtrrFix4kF0000 = 0x00080079,
	HvX64RegisterMtrrFix4kF8000 = 0x0008007A,
	HvX64RegisterBndcfgs = 0x0008007C,
	HvX64RegisterDebugCtl = 0x0008007D,
	HvX64RegisterSgxLaunchControl0 = 0x00080080,
	HvX64RegisterSgxLaunchControl1 = 0x00080081,
	HvX64RegisterSgxLaunchControl2 = 0x00080082,
	HvX64RegisterSgxLaunchControl3 = 0x00080083,
	// Other MSRs 
	HvX64RegisterMsrIa32MiscEnable = 0x000800A0,
	HvX64RegisterIa32FeatureControl = 0x000800A1,
	// Performance monitoring MSRs 
	HvX64RegisterPerfGlobalCtrl = 0x00081000,
	HvX64RegisterPerfGlobalStatus = 0x00081001,
	HvX64RegisterPerfGlobalInUse = 0x00081002,
	HvX64RegisterFixedCtrCtrl = 0x00081003,
	HvX64RegisterDsArea = 0x00081004,
	HvX64RegisterPebsEnable = 0x00081005,
	HvX64RegisterPebsLdLat = 0x00081006,
	HvX64RegisterPebsFrontend = 0x00081007,
	HvX64RegisterPerfEvtSel0 = 0x00081100,
	HvX64RegisterPmc0 = 0x00081200,
	HvX64RegisterFixedCtr0 = 0x00081300,
	HvX64RegisterLbrTos = 0x00082000,
	HvX64RegisterLbrSelect = 0x00082001,
	HvX64RegisterLerFromLip = 0x00082002,
	HvX64RegisterLerToLip = 0x00082003,
	HvX64RegisterLbrFrom0 = 0x00082100,
	HvX64RegisterLbrTo0 = 0x00082200,
	HvX64RegisterLbrInfo0 = 0x00083300,
	// Hypervisor-defined MSRs (Misc) 
	HvX64RegisterVpRuntime = 0x00090000,
	HvX64RegisterHypercall = 0x00090001,
	HvRegisterGuestOsId = 0x00090002,
	HvRegisterVpIndex = 0x00090003,
	HvRegisterTimeRefCount = 0x00090004,
	HvRegisterCpuManagementVersion = 0x00090007,
	// Virtual APIC registers MSRs 
	HvX64RegisterEoi = 0x00090010,
	HvX64RegisterIcr = 0x00090011,
	HvX64RegisterTpr = 0x00090012,
	HvRegisterVpAssistPage = 0x00090013,
	HvRegisterReferenceTsc = 0x00090017,
	// Performance statistics MSRs 
	HvRegisterStatsPartitionRetail = 0x00090020,
	HvRegisterStatsPartitionInternal = 0x00090021,
	HvRegisterStatsVpRetail = 0x00090022,
	HvRegisterStatsVpInternal = 0x00090023,
	// Partition Timer Assist Registers 
	HvX64RegisterEmulatedTimerPeriod = 0x00090030,
	HvX64RegisterEmulatedTimerControl = 0x00090031,
	HvX64RegisterPmTimerAssist = 0x00090032,
	// Hypervisor-defined MSRs (Synic) 
	HvRegisterSint0 = 0x000A0000,
	HvRegisterSint1 = 0x000A0001,
	HvRegisterSint2 = 0x000A0002,
	HvRegisterSint3 = 0x000A0003,
	HvRegisterSint4 = 0x000A0004,
	HvRegisterSint5 = 0x000A0005,
	HvRegisterSint6 = 0x000A0006,
	HvRegisterSint7 = 0x000A0007,
	HvRegisterSint8 = 0x000A0008,
	HvRegisterSint9 = 0x000A0009,
	HvRegisterSint10 = 0x000A000A,
	HvRegisterSint11 = 0x000A000B,
	HvRegisterSint12 = 0x000A000C,
	HvRegisterSint13 = 0x000A000D,
	HvRegisterSint14 = 0x000A000E,
	HvRegisterSint15 = 0x000A000F,
	HvRegisterScontrol = 0x000A0010,
	HvRegisterSversion = 0x000A0011,
	HvRegisterSifp = 0x000A0012,
	HvRegisterSipp = 0x000A0013,
	HvRegisterEom = 0x000A0014,
	HvRegisterSirbp = 0x000A0015,
	// Hypervisor-defined MSRs (Synthetic Timers) 
	HvRegisterStimer0Config = 0x000B0000,
	HvRegisterStimer0Count = 0x000B0001,
	HvRegisterStimer1Config = 0x000B0002,
	HvRegisterStimer1Count = 0x000B0003,
	HvRegisterStimer2Config = 0x000B0004,
	HvRegisterStimer2Count = 0x000B0005,
	HvRegisterStimer3Config = 0x000B0006,
	HvRegisterStimer3Count = 0x000B0007,
	HvRegisterStimeUnhaltedTimerConfig = 0x000B0100,
	HvRegisterStimeUnhaltedTimerCount = 0x000B0101,
	// 
	// XSAVE/XRSTOR register names. 
	// 
	// XSAVE AFX extended state registers. 
	HvX64RegisterYmm0Low = 0x000C0000,
	HvX64RegisterYmm1Low = 0x000C0001,
	HvX64RegisterYmm2Low = 0x000C0002,
	HvX64RegisterYmm3Low = 0x000C0003,
	HvX64RegisterYmm4Low = 0x000C0004,
	HvX64RegisterYmm5Low = 0x000C0005,
	HvX64RegisterYmm6Low = 0x000C0006,
	HvX64RegisterYmm7Low = 0x000C0007,
	HvX64RegisterYmm8Low = 0x000C0008,
	HvX64RegisterYmm9Low = 0x000C0009,
	HvX64RegisterYmm10Low = 0x000C000A,
	HvX64RegisterYmm11Low = 0x000C000B,
	HvX64RegisterYmm12Low = 0x000C000C,
	HvX64RegisterYmm13Low = 0x000C000D,
	HvX64RegisterYmm14Low = 0x000C000E,
	HvX64RegisterYmm15Low = 0x000C000F,
	HvX64RegisterYmm0High = 0x000C0010,
	HvX64RegisterYmm1High = 0x000C0011,
	HvX64RegisterYmm2High = 0x000C0012,
	HvX64RegisterYmm3High = 0x000C0013,
	HvX64RegisterYmm4High = 0x000C0014,
	HvX64RegisterYmm5High = 0x000C0015,
	HvX64RegisterYmm6High = 0x000C0016,
	HvX64RegisterYmm7High = 0x000C0017,
	HvX64RegisterYmm8High = 0x000C0018,
	HvX64RegisterYmm9High = 0x000C0019,
	HvX64RegisterYmm10High = 0x000C001A,
	HvX64RegisterYmm11High = 0x000C001B,
	HvX64RegisterYmm12High = 0x000C001C,
	HvX64RegisterYmm13High = 0x000C001D,
	HvX64RegisterYmm14High = 0x000C001E,
	HvX64RegisterYmm15High = 0x000C001F,
	// Synthetic VSM registers 
	// 
	HvRegisterVsmCodePageOffsets = 0x000D0002,
	HvRegisterVsmVpStatus = 0x000D0003,
	HvRegisterVsmPartitionStatus = 0x000D0004,
	HvRegisterVsmVina = 0x000D0005,
	HvRegisterVsmCapabilities = 0x000D0006,
	HvRegisterVsmPartitionConfig = 0x000D0007,
	HvRegisterVsmVpSecureConfigVtl0 = 0x000D0010,
	HvRegisterVsmVpSecureConfigVtl1 = 0x000D0011,
	HvRegisterVsmVpSecureConfigVtl2 = 0x000D0012,
	HvRegisterVsmVpSecureConfigVtl3 = 0x000D0013,
	HvRegisterVsmVpSecureConfigVtl4 = 0x000D0014,
	HvRegisterVsmVpSecureConfigVtl5 = 0x000D0015,
	HvRegisterVsmVpSecureConfigVtl6 = 0x000D0016,
	HvRegisterVsmVpSecureConfigVtl7 = 0x000D0017,
	HvRegisterVsmVpSecureConfigVtl8 = 0x000D0018,
	HvRegisterVsmVpSecureConfigVtl9 = 0x000D0019,
	HvRegisterVsmVpSecureConfigVtl10 = 0x000D001A,
	HvRegisterVsmVpSecureConfigVtl11 = 0x000D001B,
	HvRegisterVsmVpSecureConfigVtl12 = 0x000D001C,
	HvRegisterVsmVpSecureConfigVtl13 = 0x000D001D,
	HvRegisterVsmVpSecureConfigVtl14 = 0x000D001E,
	HvRegisterVsmVpWaitForTlbLock = 0x000D0020,
} HV_REGISTER_NAME, * PCHV_REGISTER_NAME;


//x86/x64 specific functions definition
#ifdef _WIN64
size_t ARCH_VMCALL(size_t);
size_t ARCH_VMCALL_REG_MOD(size_t);
size_t ArchmWinHvOnInterrupt(VOID);
size_t ArchXPartEnlightenedIsr(VOID);
size_t ArchmHvlRegisterInterruptCallback(UINT64 ArchmWinHvOnInterruptAddress,UINT64 HvlpInterruptCallbackAddress, UINT64 Index);
size_t ArchReadMsr(size_t MsrReg);
size_t Arch_SendVMCall(VOID);
#else
size_t _cdecl ARCH_VMCALL_MM(size_t, size_t, size_t);
size_t _cdecl ARCH_VMCALL_REG(size_t);
size_t _cdecl ARCH_VMCALL_REG_MOD(size_t);
size_t _cdecl ArchmWinHvOnInterrupt(VOID);
size_t _cdecl ArchmHvlRegisterInterruptCallback(UINT64 ArchmWinHvOnInterruptAddress,UINT64 HvlpInterruptCallbackAddress, UINT64 Index);
size_t _cdecl ArchReadMsr(size_t MsrReg);
size_t _cdecl Arch_SendVMCall(VOID);
#endif

//
// Host only API
//

#ifndef IS_GUEST

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
	_stdcall 
#endif 
	WinHvGetPartitionId(__out PHV_PARTITION_ID PartitionId);

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
	_stdcall 
#endif
	WinHvGetPartitionProperty(
	  _In_   HV_PARTITION_ID PartitionId,
	  _In_   HV_PARTITION_PROPERTY_CODE PropertyCode,
	  _Out_  PHV_PARTITION_PROPERTY PropertyValue
	);

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
	_stdcall 
#endif
	WinHvGetNextChildPartition(	__in  HV_PARTITION_ID	ParentId,__in  HV_PARTITION_ID	PreviousChildId,__out PHV_PARTITION_ID	NextChildId);

DECLSPEC_IMPORT HV_STATUS
#ifndef _WIN64
_stdcall
#endif
WinHvInstallIntercept(
	_In_  HV_PARTITION_ID PartitionId,
	_In_  UINT32 AccessType,
	_In_  PHV_INTERCEPT_DESCRIPTOR Descriptor
);

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
_stdcall 
#endif
	WinHvSetPartitionProperty(__in HV_PARTITION_ID	PartitionId,__in HV_PARTITION_PROPERTY_CODE	PropertyCode,__in HV_PARTITION_PROPERTY	PropertyValue);

#endif //IS_GUEST

DECLSPEC_IMPORT HV_STATUS 
#ifndef _WIN64
_stdcall 
#endif 
	WinHvGetLogicalProcessorRunTime(__out PHV_NANO100_TIME	GlobalTime,	__out PHV_NANO100_TIME	LocalRunTime,__out PHV_NANO100_TIME	HypervisorTime,	__out PHV_NANO100_TIME	SomethingTime);


DECLSPEC_IMPORT
HV_STATUS
#ifndef _WIN64
	_stdcall 
#endif
 WinHvSignalEvent(__in HV_CONNECTION_ID	ConnectionId,__in UINT16 FlagNumber);

//DECLSPEC_IMPORT 
//HV_STATUS 
//#ifndef _WIN64
//_stdcall 
//#endif
//	WinHvConnectPort(
//	__in HV_PARTITION_ID	ConnectionPartition,
//	__in HV_CONNECTION_ID	ConnectionId,
//	__in HV_PARTITION_ID	PortPartition,
//	__in HV_PORT_ID	PortId,
//	__in PHV_CONNECTION_INFO	ConnectionInfo,
//	__in UINT32 param6
//	);

//DECLSPEC_IMPORT HV_STATUS
//#ifndef _WIN64
//_stdcall
//#endif
//WinHvPostMessage(
//  _In_  HV_CONNECTION_ID ConnectionId,
//  _In_  HV_MESSAGE_TYPE MessageType,
//  _In_  PVOID Message,
//  _In_  UINT32 PayloadSize
//);

// https://docs.microsoft.com/pt-br/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_x64_fp_register

typedef struct
{
	UINT64 Mantissa;
	UINT64 BiasedExponent : 15;
	UINT64 Sign : 1;
	UINT64 Reserved : 48;
} HV_X64_FP_REGISTER;

typedef struct
{
	UINT64 Reg64_1;
	UINT64 Reg64_2;
} UINT128;

typedef struct
{
	UINT16 FpControl;
	UINT16 FpStatus;
	UINT8 FpTag;
	UINT8 Reserved : 8;
	UINT16 LastFpOp;
	union {
		UINT64 LastFpRip;
		struct {
			UINT32 LastFpEip;
			UINT16 LastFpCs;
		};
	};
} HV_X64_FP_CONTROL_STATUS_REGISTER;

typedef struct
{
	union
	{
		UINT64 LastFpRdp;
		struct
		{
			UINT32 LastFpDp;
			UINT16 LastFpDs;
		};
	};

	UINT32 XmmStatusControl;
	UINT32 XmmStatusControlMask;
} HV_X64_XMM_CONTROL_STATUS_REGISTER;

typedef struct
{
	UINT16 Pad[3];
	UINT16 Limit;
	UINT64 Base;
} HV_X64_TABLE_REGISTER;

union
{
	UINT64 AsUINT64;
	struct
	{
		// These bits enable instruction execution prevention for specific
		// instructions.

		UINT64 PreventSgdt : 1;
		UINT64 PreventSidt : 1;
		UINT64 PreventSldt : 1;
		UINT64 PreventStr : 1;
		UINT64 Reserved : 60;
	};
} HV_X64_MSR_NPIEP_CONFIG_CONTENTS;

typedef union _HV_EXPLICIT_SUSPEND_REGISTER {
	UINT64 AsUINT64;
	struct {
		UINT64 Suspended : 1;
		UINT64 Reserved : 63;
	};
} HV_EXPLICIT_SUSPEND_REGISTER, * PHV_EXPLICIT_SUSPEND_REGISTER;

typedef union _HV_INTERCEPT_SUSPEND_REGISTER {
	UINT64 AsUINT64;
	struct {
		UINT64 Suspended : 1;
		UINT64 TlbLocked : 1;
		UINT64 Reserved : 62;
	};
} HV_INTERCEPT_SUSPEND_REGISTER, * PHV_INTERCEPT_SUSPEND_REGISTER;

typedef union
{
	UINT128 Reg128;
	UINT64 Reg64;
	UINT32 Reg32;
	UINT16 Reg16;
	UINT8 Reg8;
	HV_X64_FP_REGISTER Fp;
	HV_X64_FP_CONTROL_STATUS_REGISTER FpControlStatus;
	HV_X64_XMM_CONTROL_STATUS_REGISTER XmmControlStatus;
	HV_X64_SEGMENT_REGISTER Segment;
	HV_X64_TABLE_REGISTER Table;
	HV_EXPLICIT_SUSPEND_REGISTER ExplicitSuspend;
	HV_INTERCEPT_SUSPEND_REGISTER InterceptSuspend;
	//HV_X64_INTERRUPT_STATE_REGISTER InterruptState;
	//HV_X64_PENDING_INTERRUPTION_REGISTER PendingInterruption;
	//HV_X64_MSR_NPIEP_CONFIG_CONTENTS NpiepConfig;
	//HV_X64_PENDING_EXCEPTION_EVENT PendingExceptionEvent;
} HV_REGISTER_VALUE, * PHV_REGISTER_VALUE;

// VTL definition 
typedef UINT8 HV_VTL; 
// Input for targeting a specific VTL. 
typedef union { 
	UINT32 AsUINT8;
	struct { 
		UINT32 TargetVtl : 8;
		UINT32 RsvdZ : 24;
		/*UINT8 TargetVtl : 4; 
		UINT8 UseTargetVtl : 1; 
		UINT8 ReservedZ : 3; */
	}; 
} HV_INPUT_VTL;

DECLSPEC_IMPORT HV_STATUS
#ifndef _WIN64
_stdcall
#endif
WinHvGetVpRegisters(
	_In_ HV_PARTITION_ID PartitionId,
	_In_ HV_VP_INDEX VpIndex,
	_In_ UINT32 InputVtl,
	_Inout_ UINT32 RegisterCount,
	UINT64 * RegisterNameList,
	UINT64 * RegisterValueLow,
	UINT64 * RegisterValueHigh
);

DECLSPEC_IMPORT HV_STATUS
#ifndef _WIN64
_stdcall
#endif
WinHvSetVpRegisters(
	__in HV_PARTITION_ID PartitionId, 
	__in HV_VP_INDEX VpIndex, 
	__in UINT32 InputVtl, 
	__inout UINT32 RegisterCount, 
	__in PUINT64 RegisterNameList,
	__in PUINT64 RegisterValueLow,
	__in PUINT64 RegisterValueHigh
);

typedef UINT64 HV_TRANSLATE_GVA_CONTROL_FLAGS;
#define HV_TRANSLATE_GVA_VALIDATE_READ 0x0001
#define HV_TRANSLATE_GVA_VALIDATE_WRITE 0x0002
#define HV_TRANSLATE_GVA_VALIDATE_EXECUTE 0x0004
#define HV_TRANSLATE_GVA_PRIVILEGE_EXEMPT 0x0008
#define HV_TRANSLATE_GVA_SET_PAGE_TABLE_BITS 0x0010
#define HV_TRANSLATE_GVA_TLB_FLUSH_INHIBIT 0x0020 
#define HV_TRANSLATE_GVA_CONTROL_MASK 0x003F
#define HV_TRANSLATE_GVA_INPUT_VTL_MASK 0xFF00000000000000

typedef enum {
	HvTranslateGvaSuccess = 0, // Translation failures 
	HvTranslateGvaPageNotPresent = 1, 
	HvTranslateGvaPrivilegeViolation = 2, 
	HvTranslateGvaInvalidPageTableFlags = 3, // GPA access failures 
	HvTranslateGvaGpaUnmapped = 4, 
	HvTranslateGvaGpaNoReadAccess = 5, 
	HvTranslateGvaGpaNoWriteAccess = 6, 
	HvTranslateGvaGpaIllegalOverlayAccess = 7, 
	// 
	// Intercept of the memory access by either
	// - a higher VTL 
	// - a nested hypervisor (due to a violation of the nested page table)
	// 
	HvTranslateGvaIntercept = 8,
} HV_TRANSLATE_GVA_RESULT_CODE;

typedef enum HV_TRANSLATE_GVA_RESULT_CODE* PHV_TRANSLATE_GVA_RESULT_CODE; 
typedef struct { 
	HV_TRANSLATE_GVA_RESULT_CODE ResultCode; 
	UINT32 CacheType : 8; 
	UINT32 OverlayPage : 1; 
	UINT32 Reserved3 : 23; 
} HV_TRANSLATE_GVA_RESULT;

#define X64_PAGE_SIZE 0x1000 
#define HV_X64_MAX_PAGE_NUMBER (MAXUINT64/X64_PAGE_SIZE) 
#define HV_PAGE_SIZE X64_PAGE_SIZE 
#define HV_LARGE_PAGE_SIZE X64_LARGE_PAGE_SIZE 
#define HV_PAGE_MASK (HV_PAGE_SIZE - 1) 
typedef UINT64 HV_SPA_PAGE_NUMBER; 
typedef UINT64 HV_GPA_PAGE_NUMBER; 
typedef UINT64 HV_GVA_PAGE_NUMBER; 
typedef UINT32 HV_SPA_PAGE_OFFSET;
typedef HV_GPA_PAGE_NUMBER *PHV_GPA_PAGE_NUMBER;

typedef struct { 
	HV_TRANSLATE_GVA_RESULT_CODE ResultCode; 
	UINT32 CacheType : 8; 
	UINT32 OverlayPage : 1; 
	UINT32 Reserved : 23; 
	//HV_X64_PENDING_EVENT EventInfo; 
} HV_TRANSLATE_GVA_RESULT_EX;

HV_STATUS WinHvTranslateVirtualAddress(
	__in HV_PARTITION_ID PartitionId, 
	__in HV_VP_INDEX VpIndex, 
	__in HV_TRANSLATE_GVA_CONTROL_FLAGS ControlFlags, 
	__in HV_GVA_PAGE_NUMBER GvaPage, 
	__out PHV_TRANSLATE_GVA_RESULT_CODE TranslationResult,
	__out PHV_GPA_PAGE_NUMBER GpaPage
);

#define HV_SYNIC_SINT_COUNT 16
typedef UINT32 HV_VP_INDEX; 
#define HV_ANY_VP 0xFFFFFFFF

//enum HV_PORT_TYPE {
//	HvPortTypeMessage = 1,
//	HvPortTypeEvent = 2,
//	HvPortTypeMonitor = 3
//} HV_PORT_TYPE, * PHV_PORT_TYPE;

//typedef struct { 
//	HV_PORT_TYPE PortType; 
//	UINT32 ReservedZ; 
//	union { 
//		struct { 
//			UINT64 ReservedZ; 
//		} MessageConnectionInfo; 
//		struct { 
//			UINT64 ReservedZ; 
//		} EventConnectionInfo; 
//		struct { 
//			HV_GPA MonitorAddress; 
//		} MonitorConnectionInfo; 
//	}; 
//} HV_CONNECTION_INFO, * PHV_CONNECTION_INFO;



//HV_STATUS WinHvConnectPort(
//	__in HV_PARTITION_ID ConnectionPartition, 
//	__in HV_CONNECTION_ID ConnectionId, 
//	__in HV_PARTITION_ID PortPartition, 
//	__in HV_PORT_ID PortId, 
//	__in PHV_CONNECTION_INFO ConnectionInfo
//);

HV_STATUS WinHvCreatePort(
	__in HV_PARTITION_ID PortPartition,
	__in UINT32 InputVtl,
	__in HV_PORT_ID PortId, 
	__in HV_PARTITION_ID ConnectionPartition, 
	__in PHV_PORT_INFO PortInfo,
	__in UINT64	unk1,
	__in UINT64	unk2
);

HV_STATUS WinHvAllocatePortId(
	__in_opt PVOID       Cookie,
	__out    PHV_PORT_ID PortId
);

HV_STATUS WinHvConnectPort(
	__in HV_PARTITION_ID ConnectionPartition,
	__in UINT32 InputVtl,
	__in HV_CONNECTION_ID ConnectionId,
	__in HV_PARTITION_ID PortPartition,
	__in HV_PORT_ID PortId,
	__in PHV_CONNECTION_INFO ConnectionInfo,
	__in UINT64	unk1
);

HV_STATUS WinHvPostMessage(
	__in HV_CONNECTION_ID ConnectionId,
	__in HV_MESSAGE_TYPE MessageType,
	__in_ecount(PayloadSize) PVOID Message,
	__in UINT32 PayloadSize
);

typedef struct {
	// Access to virtual MSRs 
	UINT64 AccessVpRunTimeReg : 1;
	UINT64 AccessPartitionReferenceCounter : 1;
	UINT64 AccessSynicRegs : 1;
	UINT64 AccessSyntheticTimerRegs : 1;
	UINT64 AccessIntrCtrlRegs : 1;
	UINT64 AccessHypercallMsrs : 1;
	UINT64 AccessVpIndex : 1;
	UINT64 AccessResetReg : 1;
	UINT64 AccessStatsReg : 1;
	UINT64 AccessPartitionReferenceTsc : 1;
	UINT64 AccessGuestIdleReg : 1;
	UINT64 AccessFrequencyRegs : 1;
	UINT64 AccessDebugRegs : 1;
	UINT64 AccessReenlightenmentControls : 1;
	UINT64 Reserved0 : 18;
	// Access to hypercalls
	UINT64 CreatePartitions : 1;
	UINT64 AccessPartitionId : 1;
	UINT64 AccessMemoryPool : 1;
	UINT64 Reserved1 : 1;
	UINT64 PostMessages : 1;
	UINT64 SignalEvents : 1;
	UINT64 CreatePort : 1;
	UINT64 ConnectPort : 1;
	UINT64 AccessStats : 1;
	UINT64 Reserved2 : 2;
	UINT64 Debugging : 1;
	UINT64 CpuManagement : 1;
	UINT64 Reserved3 : 1;
	UINT64 Reserved4 : 1;
	UINT64 Reserved5 : 1;
	UINT64 AccessVSM : 1;
	UINT64 AccessVpRegisters : 1;
	UINT64 Reserved6 : 1;
	UINT64 Reserved7 : 1;
	UINT64 EnableExtendedHypercalls : 1;
	UINT64 StartVirtualProcessor : 1;
	UINT64 Reserved8 : 10;
} HV_PARTITION_PRIVILEGE_MASK, * PHV_PARTITION_PRIVILEGE_MASK;


typedef struct HV_POSTMESSAGE_PARAMS {
	UINT32 connectionid;
	UINT32 messagetype;
} HV_POSTMESSAGE_PARAMS, * PHV_POSTMESSAGE_PARAMS;