using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultUInt16
    {
        public List<ScanValueUInt16> ScanValues { get; private set; }

        public ScanResultUInt16(List<ScanValueUInt16> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}