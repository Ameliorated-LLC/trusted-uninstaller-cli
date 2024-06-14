using System;
using System.Collections.Generic;
using System.Linq;

namespace Core
{
    public class IdManager
    {
        private readonly SortedSet<short> usedIds = new SortedSet<short>();
        private readonly object padlock = new object();

        public short GenerateId()
        {
            lock (padlock)
            {
                short maxId = usedIds.Count > 0 ? usedIds.Max() : (short)0;

                for (short i = 1; i <= maxId + 1; i++)
                {
                    if (usedIds.Add(i))
                    {
                        return i;
                    }
                }

                throw new InvalidOperationException("No available Ids left.");
            }
        }

        public void ReleaseId(short id)
        {
            lock (padlock)
            {
                usedIds.Remove(id);
            }
        }
    }
}