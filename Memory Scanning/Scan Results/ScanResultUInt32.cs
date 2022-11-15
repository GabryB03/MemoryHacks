using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultUInt32
    {
        public List<ScanValueUInt32> ScanValues { get; private set; }

        public ScanResultUInt32(List<ScanValueUInt32> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}