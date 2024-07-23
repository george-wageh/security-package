using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{


    public class DiffieHellman
    {

        public int power(int f, int s, int sf)
        {
            int r = 1;
            int mod = sf;
            int pow = f;
            int i = 1;
            while (true)
            {
                r = ((r * pow) % mod);
                i++;
                if (!(i <= s))
                    break;
            }
            return r;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int[] keys = new int[2] {
                power(power(alpha, xb, q), xa, q),
                power(power(alpha, xa, q), xb, q)
            };
            return keys.ToList();
        }
    }
}