using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        int[,] mm(int[,]  a, int[,]  b , int PTm) {
            int[,] res = new int[PTm, PTm];
            for (int i = 0; i < PTm; i++)
            {
                for (int j = 0; j < PTm; j++)
                {
                    for (int k = 0; k < PTm; k++)
                    {
                        res[i, j] += a[i, k] * b[k, j];
                    }
                }
            }
            return res;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int PTm = 2;
            int[,] PTMatrix = new int[PTm, PTm];
            int[,] cipher3Matrix = new int[PTm, PTm];
            bool ff = false;
            for (int fff = 0; fff < cipherText.Count/ PTm; fff++) {
                for (int ddd = 0; ddd < cipherText.Count/ PTm; ddd++)
                {
                    if (fff != ddd) {

                        PTMatrix[0, 0] = (int)plainText[(2 * fff)];
                        PTMatrix[1, 0] = (int)plainText[(2 * fff) + 1];
                        PTMatrix[0, 1] = (int)plainText[(2 * ddd)];
                        PTMatrix[1, 1] = (int)plainText[(2 * ddd) + 1];
                        try
                        {
                            PTMatrix = inverse(PTMatrix);

                            cipher3Matrix[0, 0] = (int)cipherText[(2 * fff)];
                            cipher3Matrix[1, 0] = (int)cipherText[(2 * fff) + 1];
                            cipher3Matrix[0, 1] = (int)cipherText[(2 * ddd)];
                            cipher3Matrix[1, 1] = (int)cipherText[(2 * ddd) + 1];
                            ff = true;
                            break;
                        }
                        catch (Exception E) { }
                    }
                }
                if (ff) {
                    break;
                }
            }
            if (ff == false) {
                throw new InvalidAnlysisException();
            }

            int[,] key = mm( cipher3Matrix, PTMatrix, 2);


            List<int> kList = new List<int>();
            for (int j = 0; j < PTm; j++)
            {
                for (int i = 0; i < PTm; i++)
                {
                    kList.Add((key[j, i] % 26 + 26) % 26);
                }
            }

            return kList;


        }
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> plainList = new List<int>();
            List<int> cipherList = new List<int>();
            foreach (char c in plainText)
            {
                plainList.Add((int)c - 97);
            }
            foreach (char c in cipherText)
            {
                cipherList.Add((int)c - 97);
            }
            List<int> keyList = Analyse(plainList, cipherList);
            string key = "";
            foreach (int c in keyList)
            {
                key += (char)(c + 97);
            }
            return key;
        }
        int GCD(int a, int b)
        {
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }
        int[,] inverse(int[,] key) {
            int m = key.GetLength(0);
            int[,] IkeyMatrix = new int[m, m];
            if (m == 2)
            {
                int det = key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0];
                det = ((det % 26) + 26) % 26;
                if (GCD(26, det) != 1)
                {
                    throw new Exception();
                }
                bool f = false;
                for (int i = 1; i < 26; i++)
                {
                    if ((det * i) % 26 == 1)
                    {
                        det = i;
                        f = true;
                        break;
                    }
                }
                if (!f)
                {
                    throw new Exception();
                }
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        if (i == j)
                            IkeyMatrix[i, j] = (det*key[(i + 1) % 2, (j + 1) % 2] % 26 + 26) % 26; 
                        else
                            IkeyMatrix[i, j] = ((-det *key[i, j]) % 26 + 26)%26;
                    }
                }
                return IkeyMatrix;
            }
            else {
               int det = key[0, 0] * (key[1, 1] * key[2, 2] - key[1, 2] * key[2, 1]) -
               key[0, 1] * (key[1, 0] * key[2, 2] - key[1, 2] * key[2, 0]) +
               key[0, 2] * (key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]);
                det = ((det % 26) + 26) % 26;
                IkeyMatrix[0, 0] = (key[1, 1] * key[2, 2] - key[1, 2] * key[2, 1]) ;
                IkeyMatrix[0, 1] = (key[0, 2] * key[2, 1] - key[0, 1] * key[2, 2]) ;
                IkeyMatrix[0, 2] = (key[0, 1] * key[1, 2] - key[0, 2] * key[1, 1]) ;
                IkeyMatrix[1, 0] = (key[1, 2] * key[2, 0] - key[1, 0] * key[2, 2]) ;
                IkeyMatrix[1, 1] = (key[0, 0] * key[2, 2] - key[0, 2] * key[2, 0]) ;
                IkeyMatrix[1, 2] = (key[0, 2] * key[1, 0] - key[0, 0] * key[1, 2]) ;
                IkeyMatrix[2, 0] = (key[1, 0] * key[2, 1] - key[1, 1] * key[2, 0]) ;
                IkeyMatrix[2, 1] = (key[0, 1] * key[2, 0] - key[0, 0] * key[2, 1]) ;
                IkeyMatrix[2, 2] = (key[0, 0] * key[1, 1] - key[0, 1] * key[1, 0]) ;
                if (GCD(26 , det)!=1)
                {
                    throw new Exception();
                }
                bool f = false;
                for (int i = 1; i < 26; i++) {
                    if ((det * i) % 26 == 1) {
                        det = i;
                        f=true;
                        break;
                    }
                }
                if (!f)
                {
                    throw new Exception();
                }
                IkeyMatrix[0, 0] = ((((IkeyMatrix[0, 0] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[0, 1] = ((((IkeyMatrix[0, 1] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[0, 2] = ((((IkeyMatrix[0, 2] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[1, 0] = ((((IkeyMatrix[1, 0] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[1, 1] = ((((IkeyMatrix[1, 1] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[1, 2] = ((((IkeyMatrix[1, 2] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[2, 0] = ((((IkeyMatrix[2, 0] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[2, 1] = ((((IkeyMatrix[2, 1] % 26) + 26) % 26)*det)%26;
                IkeyMatrix[2, 2] = ((((IkeyMatrix[2, 2] % 26) + 26) % 26)*det)%26;
                return IkeyMatrix;
            }                                     
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            //throw new NotImplementedException();
            int m = 2;
            if (key.Count == 9)
                m = 3;
            int[,] keyMatrix = new int[m, m];

            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        keyMatrix[i, j] = (int)key[j + m * i];
                        if (!(keyMatrix[i, j] >= 0 && keyMatrix[i, j] < 26)) {
                            throw new System.Exception();
                        }
                    }
                }
            }
            int[,] IkeyMatrix = inverse(keyMatrix);

            List<int> plainTest = new List<int>();
            for (int i = 0; i < cipherText.Count; i += m)
            {
                List<int> tmp = new List<int>();
                {
                    for (int j = 0; j < m; j++)
                    {
                        tmp.Add(cipherText[i + j]);
                    }
                }
                {
                    for (int j = 0; j < m; j++)
                    {
                        int v = 0;
                        for (int k = 0; k < m; k++)
                        {
                            v += IkeyMatrix[j, k] * tmp[k];
                        }
                        plainTest.Add(((v % 26) + 26)%26);
                    }
                }
            }
            return plainTest;


        }
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            List<int> cipherList = new List<int>();
            List<int> keyList = new List<int>();
            foreach (char c in cipherText)
            {
                cipherList.Add((int)c - 97);
            }
            foreach (char c in key)
            {
                keyList.Add((int)c - 97);
            }
            List<int> plainLost = Decrypt(cipherList, keyList);
            string cipher = "";
            foreach (int c in plainLost)
            {
                cipher += (char)(c + 97);
            }
            return cipher;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int m = 2;
            if (key.Count == 9)
                m = 3;
            byte[,] keyMatrix ;
            keyMatrix = new byte[m, m];
            {
                for (int i = 0; i < m;i++)
                {
                    for (int j = 0; j < m; j++) { 
                        keyMatrix[i, j] = (byte)key[j+m*i];
                    }
                }
            }
            List<int> cipherList = new List<int>();
            for (int i = 0; i < plainText.Count; i+=m) {
                List<int> tmp = new List<int>();
                { 
                    for (int j = 0; j < m; j++) {
                        tmp.Add(plainText[i + j]);
                    }
                }
                { 
                    for (int j = 0; j < m; j++) {
                        int v = 0;
                        for (int k = 0; k < m; k++)
                        {
                            v += keyMatrix[j , k]* tmp[k];
                        }
                        cipherList.Add(v % 26);
                    }
                }
            }
            return cipherList;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            List<int> plainList = new List<int>();
            List<int> keyList = new List<int>();
            foreach (char c in plainText) { 
                plainList.Add((int)c-97);
            }
            foreach (char c in key)
            {
                keyList.Add((int)c-97);
            }
            List<int>  cipherList = Encrypt(plainList, keyList);
            string cipher = "";
            foreach (int c in cipherList)
            {
                cipher += (char)(c + 97);
            }
            return cipher;
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            int PTm = 3;
            int[,] PTMatrix = new int[PTm, PTm];
            int[,] cipher3Matrix = new int[PTm, PTm];
            bool ff = false;

            for (int fff = 0; fff < cipher3.Count / PTm; fff++)
            {
                for (int rrr = 0; fff < cipher3.Count / PTm; fff++) {
                    for (int ddd = 0; ddd < cipher3.Count / PTm; ddd++)
                    {
                        if ((fff != ddd) && (fff != rrr) && (ddd != rrr))
                        {

                            PTMatrix[0, 0] = (int)plain3[(3 * fff)];
                            PTMatrix[1, 0] = (int)plain3[(3 * fff) + 1];
                            PTMatrix[2, 0] = (int)plain3[(3 * fff) + 2];

                            PTMatrix[0, 1] = (int)plain3[(3 * rrr)];
                            PTMatrix[1, 1] = (int)plain3[(3 * rrr) + 1];
                            PTMatrix[2, 1] = (int)plain3[(3 * rrr) + 2];

                            PTMatrix[0, 2] = (int)plain3[(3 * ddd)];
                            PTMatrix[1, 2] = (int)plain3[(3 * ddd) + 1];
                            PTMatrix[2, 2] = (int)plain3[(3 * ddd) + 2];
                            try
                            {
                                PTMatrix = inverse(PTMatrix);

                                cipher3Matrix[0, 0] = (int)cipher3[(3 * fff)];
                                cipher3Matrix[1, 0] = (int)cipher3[(3 * fff) + 1];
                                cipher3Matrix[2, 0] = (int)cipher3[(3 * fff) + 2];
                                
                                cipher3Matrix[0, 1] = (int)cipher3[(3 * rrr)];
                                cipher3Matrix[1, 1] = (int)cipher3[(3 * rrr) + 1];
                                cipher3Matrix[2, 1] = (int)cipher3[(3 * rrr) + 2];
                                              
                                cipher3Matrix[0, 2] = (int)cipher3[(3 * ddd)];
                                cipher3Matrix[1, 2] = (int)cipher3[(3 * ddd) + 1];
                                cipher3Matrix[2, 2] = (int)cipher3[(3 * ddd) + 2];
                                ff = true;
                                break;
                            }
                            catch (Exception E) { }
                        }
                    }
                    if (ff)
                    {
                        break;
                    }

                }
                if (ff)
                {
                    break;
                }
            }
            if (ff == false)
            {
                throw new InvalidAnlysisException();
            }

            int[,] key = mm(cipher3Matrix, PTMatrix, 3);

            List<int> kList = new List<int>();
            for (int j = 0; j < PTm; j++)
            {
                for (int i = 0; i < PTm; i++)
                {
                    kList.Add(key[j,i]%26);
                }
            }

            return kList;

        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            plain3 = plain3.ToLower();
            cipher3 = cipher3.ToLower();
            List<int> plainList = new List<int>();
            List<int> cipherList = new List<int>();
            foreach (char c in plain3)
            {
                plainList.Add((int)c - 97);
            }
            foreach (char c in cipher3)
            {
                cipherList.Add((int)c - 97);
            }
            List<int> keyList = Analyse3By3Key(plainList, cipherList);
            string key = "";
            foreach (int c in keyList)
            {
                key += (char)(c + 97);
            }
            return key;
        }
    }
}

