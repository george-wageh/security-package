using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = 0;
            for (int i = 1; i < plainText.Length; i++)
            {
                if (plainText[i] == cipherText[1])
                {
                    break;
                }
                else
                {
                    key++;
                }
            }
            key = key + 1;
            if (key == 1)
            {
                if (plainText.Equals(cipherText))
                {

                }
                else
                {
                    key = 2;
                    for (int i = 2; i < plainText.Length; i++)
                    {

                        if (plainText[i] == cipherText[1])
                        {
                            break;
                        }
                        else
                        {
                            key++;
                        }
                    }

                }

            }


            return key;


        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string plainText = "";
            int adder = (cipherText.Length) / key;
            if (cipherText.Length % key > 0)
            {
                adder = adder + 1;
            }
            for (int i = 0; i < adder; i++)
            {
                for (int j = i; j < cipherText.Length; j += adder)
                {
                    plainText += cipherText[j];
                }
            }


            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            plainText = plainText.ToLower();
            string cipherText = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = i; j < plainText.Length; j += key)
                {
                    cipherText += plainText[j];
                }
            }

            return cipherText;
        }
    }
}
