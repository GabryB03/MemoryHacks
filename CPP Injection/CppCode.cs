using System.Collections.Generic;

namespace MemoryHacks
{
    public class CppCode
    {
        public string DllMainCode { get; set; }
        public string BeforeDllMainCode { get; set; }
        public string AfterDllMainCode { get; set; }
        public List<CppInclude> Includes { get; set; }

        public CppCode(string dllMainCode, List<CppInclude> includes = null, string beforeDllMainCode = "", string afterDllMainCode = "")
        {
            DllMainCode = dllMainCode;
            BeforeDllMainCode = beforeDllMainCode;
            AfterDllMainCode = afterDllMainCode;

            if (includes == null)
            {
                Includes = new List<CppInclude>();
            }
            else
            {
                Includes = includes;
            }
        }
    }
}