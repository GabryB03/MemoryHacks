using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultInt64
    {
        public List<ScanValueInt64> ScanValues { get; private set; }

        public ScanResultInt64(List<ScanValueInt64> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}