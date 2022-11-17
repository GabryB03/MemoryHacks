namespace MemoryHacks
{
    public enum CreateThreadFunction
    {
        CreateRemoteThread,
        RtlCreateUserThread,
        NtCreateThreadEx,
        ZwCreateThreadEx
    }
}