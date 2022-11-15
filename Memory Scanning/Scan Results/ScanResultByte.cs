using System.Collections.Generic;

namespace MemoryHacks
{
    public class ScanResultByte
    {
        public List<ScanValueByte> ScanValues { get; private set; }

        public ScanResultByte(List<ScanValueByte> scanValues)
        {
            ScanValues = scanValues;
        }
    }
}