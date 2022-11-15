using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultString
    {
        public List<ScanValueString> ScanValues { get; private set; }

        public ScanResultString(List<ScanValueString> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}