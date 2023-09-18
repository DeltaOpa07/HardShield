#include "SystemInfo.h"

INT SysInfo::GetMaxThreadNum()
{
	SYSTEM_INFO stSysInfo = { 0 };
	GetNativeSystemInfo(&stSysInfo);
	
	return(stSysInfo.dwNumberOfProcessors * 3 / 2);
}
