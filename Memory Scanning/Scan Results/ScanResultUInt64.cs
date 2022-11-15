using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultUInt64
    {
        public List<ScanValueUInt64> ScanValues { get; private set; }

        public ScanResultUInt64(List<ScanValueUInt64> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}