# Enlighten Me Pt.1 & Pt.2
## Summary:
Enlightenme driver runs on both, host and guest hyper-v VMs.

When running on host machines, it setups a port for inter-partition communication and registers itself to receive the following Hyper-V's messages:
 - HvMessageTypeX64CpuidIntercept

	When receiving the HvMessageTypeX64CpuidIntercept, the driver emulates a cpuid response (Vulnerable).
 - Custom message

	When receiving the custom message, the driver install an HvInterceptTypeX64Cpuid Intercept.

The driver also provides 4 IOCTL features:
	- reads base address
	- writes byte to given address
	- reads byte from given address
	- calls WinHvPostMessage

So the first step is to write an executable that interacts with the driver and use its own functions to read the flag from guest's kernel space.

Second step requires to bypass WinHvpConnected check made in winhvr!WinHvpHypercall in guest VM in order to call WinHvPostMessage so the Intercept gets installed, turning then the host vulnerable to OOB reads throught  the CPUID intecerpt, then exploit with CPUID instructions to read the flag from host's kernel space.

## References
Special thanks to @gerhart_x for his amazing research on Hyper-V!

http://hvinternals.blogspot.com/2015/10/hyper-v-internals.html\
https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/hyper-v-architecture
