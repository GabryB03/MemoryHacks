using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultByteArray
    {
        public List<ScanValueByteArray> ScanValues { get; private set; }

        public ScanResultByteArray(List<ScanValueByteArray> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}