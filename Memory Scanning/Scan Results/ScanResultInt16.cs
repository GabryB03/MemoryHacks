using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultInt16
    {
        public List<ScanValueInt16> ScanValues { get; private set; }

        public ScanResultInt16(List<ScanValueInt16> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}