using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        int[,] sBox1 = {
            { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
            {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
            {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
            { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
        };
        int[,] sBox2 = {
            { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
            { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
            { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
            { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };

        int[,] sBox3 = {
            { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
            { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
            { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
            { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] sBox4 = {
            { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
            { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
            { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
            { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] sBox5 = {
            { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
            { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
            { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
            { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] sBox6 = {
            { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
            { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
            { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
            { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] sBox7 = {
            { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
            { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
            { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
            { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] sBox8 = {
            { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
            { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
            { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
            { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

        int[] numShift = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };



        string[] mapHexToBinary = {"0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111",
            "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111"
        };
        int parse_(char x)
        {
            if (x == 'A' || x == 'a')
                return 10;
            else if (x == 'B' || x == 'b')
                return 11;
            else if (x == 'C' || x == 'c')
                return 12;
            else if (x == 'D' || x == 'd')
                return 13;
            else if (x == 'E' || x == 'e')
                return 14;
            else if (x == 'F' || x == 'f')
                return 15;
            else
                return (int)x - (int)'0';
        }
        string hexToBin(string hex)
        {
            string key_b = "";
            for (int i = 2; i < hex.Length; i++)
                key_b += (mapHexToBinary[parse_(hex[i])]);
            return key_b;
        }
        string binToHex(string binary)
        {
            string a = "";
            for (int i = 0; i < binary.Length; i += 4)
            {
                string v = binary.Substring(i, 4);
                for (int j = 0; j < mapHexToBinary.Length; j++)
                {
                    if (v == mapHexToBinary[j])
                    {
                        if (j < 10)
                        {
                            a += j.ToString();
                        }
                        else
                        {
                            if (j == 10)
                                a += 'A';
                            else if (j == 11)
                                a += 'B';
                            else if (j == 12)
                                a += 'C';
                            else if (j == 13)
                                a += 'D';
                            else if (j == 14)
                                a += 'E';
                            else if (j == 15)
                                a += 'F';
                        }
                        break;
                    }
                }
            }
            return "0x" + a;
        }
        int[] pc1 = new int[]
            {
            57 , 49 , 41 , 33 , 25 , 17 , 9  ,
            1  , 58 , 50 , 42 , 34 , 26 , 18 ,
            10 , 2  , 59 , 51 , 43 , 35 , 27 ,
            19 , 11 , 3  , 60 , 52 , 44 , 36 ,
            63 , 55 , 47 , 39 , 31 , 23 , 15 ,
            7  , 62 , 54 , 46 , 38 , 30 , 22 ,
            14 , 6  , 61 , 53 , 45 , 37 , 29 ,
            21 , 13 , 5  , 28 , 20 , 12 , 4 };
        int[] pc2 = new int[]
            {
            14 , 17 , 11 , 24 , 1  , 5 ,
            3  , 28 , 15 , 6  , 21 , 10,
            23 , 19 , 12 , 4  , 26 , 8 ,
            16 , 7  , 27 , 20 , 13 , 2 ,
            41 , 52 , 31 , 37 , 47 , 55,
            30 , 40 , 51 , 45 , 33 , 48,
            44 , 49 , 39 , 56 , 34 , 53,
            46 , 42 , 50 , 36 , 29 , 32};
        int[] ip = new int[] {
            58 , 50 , 42 , 34 , 26 , 18 , 10 , 2,
            60 , 52 , 44 , 36 , 28 , 20 , 12 , 4,
            62 , 54 , 46 , 38 , 30 , 22 , 14 , 6,
            64 , 56 , 48 , 40 , 32 , 24 , 16 , 8,
            57 , 49 , 41 , 33 , 25 , 17 , 9  , 1,
            59 , 51 , 43 , 35 , 27 , 19 , 11 , 3,
            61 , 53 , 45 , 37 , 29 , 21 , 13 , 5,
            63 , 55 , 47 , 39 , 31 , 23 , 15 , 7
        };

        int[] expansionMat = new int[]{
            32 , 1  , 2  , 3  , 4  , 5 ,
            4  , 5  , 6  , 7  , 8  , 9 ,
            8  , 9  , 10 , 11 , 12 , 13,
            12 , 13 , 14 , 15 , 16 , 17,
            16 , 17 , 18 , 19 , 20 , 21,
            20 , 21 , 22 , 23 , 24 , 25,
            24 , 25 , 26 , 27 , 28 , 29,
            28 , 29 , 30 , 31 , 32 , 1
        };
        int[] pf = {
            16 , 7  , 20 , 21 , 29 , 12 , 28 , 17,
            1  , 15 , 23 , 26 , 5  , 18 , 31 , 10,
            2  , 8  , 24 , 14 , 32 , 27 , 3  , 9,
            19 , 13 , 30 , 6  , 22 , 11 , 4  , 25
        };

        int[] pff = {
            40, 8 , 48 , 16 , 56 , 24 , 64 , 32,
            39, 7 , 47 , 15 , 55 , 23 , 63 , 31,
            38, 6 , 46 , 14 , 54 , 22 , 62 , 30,
            37, 5 , 45 , 13 , 53 , 21 , 61 , 29,
            36, 4 , 44 , 12 , 52 , 20 , 60 , 28,
            35, 3 , 43 , 11 , 51 , 19 , 59 , 27,
            34, 2 , 42 , 10 , 50 , 18 , 58 , 26,
            33, 1 , 41 , 9  , 49 , 17 , 57 , 25
        };
        string permutation(string a, int[] src)
        {
            string b = "";
            for (int i = 0; i < src.Length; i++)
                b += a[src[i] - 1];
            return b;
        }

        string shift(string a, int m)
        {
            string b = "";
            for (int i = 0; i < a.Length; i++)
            {
                b += a[(i + m) % a.Length];
            }
            return b;
        }
        string[] splitString(string a)
        {
            int m = a.Length / 2;
            string b = "";
            string c = "";
            for (int i = 0; i < a.Length; i++)
            {
                if (i < m)
                    b += a[i];
                else
                    c += a[i];
            }
            return new string[] { b, c };
        }
        string[] create16keys(string a)
        {
            List<string> list = new List<string>();
            string a1 = a;

            for (int i = 0; i < numShift.Length; i++)
            {
                a1 = shift(a1, numShift[i]);
                list.Add(a1);
            }
            return list.ToArray();
        }

        string XorString(string r, string key)
        {
            string a = "";
            for (int i = 0; i < r.Length; i++)
            {
                int v = r[i] + key[i] - 2 * '0';
                if (v % 2 == 0)
                    a += '0';
                else
                    a += '1';
            }
            return a;
        }
        string GetVsBox(string a, int index)
        {
            int i = a[0] * 2 + a[5] - 3 * '0';
            int j = a[1] * 8 + a[2] * 4 + a[3] * 2 + a[4] * 1 - 15 * '0';
            int[,] sBox = null;
            if (index == 0)
                sBox = sBox1;
            else if (index == 1)
                sBox = sBox2;
            else if (index == 2)
                sBox = sBox3;
            else if (index == 3)
                sBox = sBox4;
            else if (index == 4)
                sBox = sBox5;
            else if (index == 5)
                sBox = sBox6;
            else if (index == 6)
                sBox = sBox7;
            else if (index == 7)
                sBox = sBox8;
            int v = sBox[i, j];
            return mapHexToBinary[v];
        }

        string applySbox(string a)
        {
            string b = "";
            for (int i = 0; i < a.Length; i += 6)
            {
                string v = a.Substring(i, 6);
                b += GetVsBox(v, i / 6);
            }

            return b;
        }


        string ManglerFun(string r, string key)
        {
            r = permutation(r, expansionMat);
            r = XorString(r, key);
            r = applySbox(r);
            r = permutation(r, pf);
            return r;
        }
        public override string Encrypt(string plainText, string key)
        {
            string key_b = hexToBin(key);
            string plain_b = hexToBin(plainText);
            string plain_ip = permutation(plain_b, ip);

            string[] temp = splitString(plain_ip);
            string L = temp[0];
            string R = temp[1];

            temp = splitString(permutation(key_b, pc1));
            string[] c_16 = create16keys(temp[0]);
            string[] d_16 = create16keys(temp[1]);
            for (int i = 0; i < 16; i++)
            {
                string R_ = XorString(L, ManglerFun(R, permutation(c_16[i] + d_16[i], pc2)));
                L = R;
                R = R_;
            }
            string cipher_b = permutation(R + L, pff);
            return binToHex(cipher_b);
        }

        public override string Decrypt(string cipherText, string key)
        {
            string key_b = hexToBin(key);
            string[] temp = splitString(permutation(key_b, pc1));
            string[] c_16 = create16keys(temp[0]);
            string[] d_16 = create16keys(temp[1]);

            string cipher_b = hexToBin(cipherText);
            string cipher_ip = permutation(cipher_b, ip);

            temp = splitString(cipher_ip);
            string L = temp[0];
            string R = temp[1];

            for (int i = 0; i < 16; i++)
            {
                string R_ = XorString(L, ManglerFun(R, permutation(c_16[16 - 1 - i] + d_16[16 - 1 - i], pc2)));
                L = R;
                R = R_;
            }
            string plain_ip = permutation(R + L, pff);
            return binToHex(plain_ip);
        }
    }
}