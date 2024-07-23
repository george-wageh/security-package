using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
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

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> list = new List<long>();
            if (m < alpha && k < alpha)
            {
                int K = power(y, k, q);
                //  B p = Math.Pow((double)y, (double)k);
                //douqble K = p % q;
                double p2 = Math.Pow((double)alpha, (double)k);
                int c1 = power(alpha, k, q);
                int c2 = (K * m) % q;
                list.Add((long)c1);
                list.Add((long)c2);


            }
            return list;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            // throw new NotImplementedException();

            int K = power(c1, x, q);

            int kpow = power(K, (q - 2), q);
            int M = power((c2 * kpow), 1, q);

            return (int)M;
        }



    }
}
