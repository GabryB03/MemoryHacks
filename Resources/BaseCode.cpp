#INCLUDES_CODE#

#BEFORE_DLL_MAIN_CODE#

DWORD WINAPI DllProcess(LPVOID lpParam)
{
	#CODE_INTO_DLL_MAIN#
	return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
		CreateThread(0, 0, DllProcess, 0, 0, 0);   
    }

    return TRUE;
}

#AFTER_DLL_MAIN_CODE#