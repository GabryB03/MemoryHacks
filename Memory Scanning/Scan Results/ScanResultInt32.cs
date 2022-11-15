using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultInt32
    {
        public List<ScanValueInt32> ScanValues { get; private set; }

        public ScanResultInt32(List<ScanValueInt32> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}