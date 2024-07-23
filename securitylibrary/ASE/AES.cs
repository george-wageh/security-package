using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        byte[,]  s_Box = new byte[,] {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };
        byte[,] s_Box_in = new byte[16, 16]; 
        byte[] rcon2 = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        public override string Decrypt(string cipherText, string key)
        {
            for (int a = 0; a < 16; a++)
            {
                for (int b = 0; b < 16; b++)
                {
                    int l = s_Box[a, b]/16;
                    int r = s_Box[a, b]%16;
                    s_Box_in[l, r] = (byte)(a * 16 + b);
                  
                }
            }
            int[,] cipherText_ = SplitIntoMatrix(cipherText);
            int[,] key_ = SplitIntoMatrix(key);
            int[,] key_n = key_;
            List<int[,]> keys_ = new List<int[,]>();
            for (int i = 0; i < 10; i++)
            {
                int[,] a = keySchedule(key_n, i);
                keys_.Add(a);
                key_n = a;
            }
            int[,]  aa = addRoundKey(cipherText_, key_n);
            aa = shiftRows_in(aa);
            aa = subBytes_in(aa);
            for (int i = 8; i >= 0; i--) {
                aa = addRoundKey(aa, keys_[i]);
                aa = mixColumn_in(aa);
                aa = shiftRows_in(aa);
                aa = subBytes_in(aa);
            }

            aa = addRoundKey(aa, key_);

            string str = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp = aa[j, i].ToString("X");
                    if (temp.Length == 1)
                    {
                        str += "0";
                    }
                    str += temp;
                }
            }
            return "0x" + str;
        }

        public override string Encrypt(string plainText, string key)
        {
            int[,] plainText_ = SplitIntoMatrix(plainText);
            int[,] key_ = SplitIntoMatrix(key);
            int[,] initAddRound = addRoundKey(plainText_, key_);
            int[,] a = initAddRound;
            int[,] key_n = key_;
            for (int i = 0; i < 9; i++) { 
               a = subBytes(a);
               a = shiftRows(a);
               a = mixColumn(a);
               key_n = keySchedule(key_n, i);
               a = addRoundKey(a, key_n);
            }
            a = subBytes(a);
            a = shiftRows(a);
            key_n = keySchedule(key_n, 9);
            a = addRoundKey(a, key_n);
            string str = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string temp = a[j, i].ToString("X");
                    if (temp.Length == 1) {
                        str += "0";
                    }
                    str += temp;
                }
            }
            return "0x"+ str;
        }
        int parse_(char x) {
            if (x == 'A'|| x == 'a')
            {
                return 10;
            }
            else if (x == 'B' || x == 'b')
            {
                return 11;
            }
            else if (x == 'C' || x == 'c')
            {
                return 12;
            }
            else if (x == 'D' || x == 'd')
            {
                return 13;
            }
            else if (x == 'E' || x == 'e')
            {
                return 14;
            }
            else if (x == 'F' || x == 'f')
            {
                return 15;
            }
            else { 
                return (int)x - (int)'0';
            }
        }
        int[,] SplitIntoMatrix(string input)
        {
            Console.WriteLine(input);
            input = input.Remove(0, 2);
            int pairsCount = (input.Length / 2);
            string[] pairs = new string[pairsCount];

            for (int i = 0; i < pairsCount; i++)
            {
                pairs[i] = input.Substring(i * 2, 2);
            }
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mtx[i, j] = (parse_(pairs[i + j * 4][0])) * 16 + (parse_(pairs[i + j * 4][1])) ;
                    Console.Write(mtx[i, j]);
                    Console.Write(" ");
                }
                Console.WriteLine("\n");

            }


            return mtx;
        }
        int[,] addRoundKey(int[,] state , int[,] key)
        {
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mtx[i, j] = state[i,j] ^ key[i , j];
                }
            }
            return mtx;
        }
       
        int[,] subBytes(int[,] state)
        {
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int l = state[i, j] / 16;
                    int r = state[i, j] % 16;
                    mtx[i, j] = (int)s_Box[l, r];
                }
            }
            return mtx;
        }
        int[,] subBytes_in(int[,] state)
        {
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int l = state[i, j] / 16;
                    int r = state[i, j] % 16;
                    mtx[i, j] = (int)s_Box_in[l, r];
                }
            }
            return mtx;
        }
        int[,] shiftRows(int[,] state)
        {
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mtx[i, j] = state[i, (j + i) % 4];
                }
            }
            return mtx;
        }
        int[,] shiftRows_in(int[,] state)
        {
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mtx[i, j] = state[i, (((j - i) % 4) + 4) % 4];
                }
            }
            return mtx;
        }
        int[,] mixColumn_in(int[,] state)
        {
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                int a = state[0, i];
                int b = state[1, i];
                int c = state[2, i];
                int d = state[3, i];

                mtx[0, i] = gfMult2N(a, 14) ^ gfMult2N(b, 11) ^ gfMult2N(c, 13) ^ gfMult2N(d, 9);
                mtx[1, i] = gfMult2N(a, 9) ^  gfMult2N(b, 14) ^ gfMult2N(c, 11) ^ gfMult2N(d, 13);
                mtx[2, i] = gfMult2N(a, 13) ^ gfMult2N(b, 9) ^  gfMult2N(c, 14) ^ gfMult2N(d, 11);
                mtx[3, i] = gfMult2N(a, 11) ^ gfMult2N(b, 13) ^ gfMult2N(c, 9) ^ gfMult2N(d, 14);
            }
            return mtx;
        }

        int[,] mixColumn(int[,] state) { 
            int[,] mtx = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                int a = state[0, i];
                int b = state[1, i];
                int c = state[2, i];
                int d = state[3, i];
                mtx[0, i] = gfMult2N(a, 2) ^ gfMult2N(b, 3) ^ gfMult2N(c, 1) ^ gfMult2N(d, 1);
                mtx[1, i] = gfMult2N(a, 1) ^ gfMult2N(b, 2) ^ gfMult2N(c, 3) ^ gfMult2N(d, 1);
                mtx[2, i] = gfMult2N(a, 1) ^ gfMult2N(b, 1) ^ gfMult2N(c, 2) ^ gfMult2N(d, 3);
                mtx[3, i] = gfMult2N(a, 3) ^ gfMult2N(b, 1) ^ gfMult2N(c, 1) ^ gfMult2N(d, 2);
            }
            return mtx;
        }
        int gfMult2N(int a, int b)
        {
            //80 hex == 128
            //0x11B hex == 283
            int re = 0;
            for(; b > 0; b >>= 1)
            {
                if ((b & 1) != 0)
                    re = re ^ a;                  
                if (a > 127) {
                    a *= 2;
                    a ^= 283;
                } 
                else {
                    a *= 2;
                }
            }
            return re;
        }

        int[,] keySchedule(int[,] key , int r)
        {
            int[,] mtx = new int[4, 4];
            int a = key[1, 3] ;
            int b = key[2, 3] ;
            int c = key[3, 3] ;
            int d = key[0, 3];
            int[,] temp = new int[,] { { a , 0 , 0 ,0}  , { 0, b, 0, 0 }, { 0, 0, c, 0 }, { 0, 0, 0, d } };
            temp = subBytes(temp);
            for (int i = 0; i < 4; i++)
            {
                if (i == 0)
                {
                    mtx[0, i] = key[0, i] ^ temp[0, 0] ^ rcon2[r] ;
                    mtx[1, i] = key[1, i] ^ temp[1, 1] ^ 0 ;
                    mtx[2, i] = key[2, i] ^ temp[2, 2] ^ 0 ;
                    mtx[3, i] = key[3, i] ^ temp[3, 3] ^ 0 ;
                }
                else {
                    mtx[0, i] = mtx[0, i - 1] ^ key[0, i] ;
                    mtx[1, i] = mtx[1, i - 1] ^ key[1, i] ;
                    mtx[2, i] = mtx[2, i - 1] ^ key[2, i] ;
                    mtx[3, i] = mtx[3, i - 1] ^ key[3, i] ;
                }
            }
            return mtx;
        }
    }
}