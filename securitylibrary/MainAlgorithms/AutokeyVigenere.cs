using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            Dictionary<(char, char), char> matrix = new Dictionary<(char, char), char>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int v = (i + j) % 26;
                    matrix.Add(((char)(i + 97), (char)(j + 97)), (char)(v + 97));
                }
            }
            //Bgib el key 3al plain wel cipher ely mdeholi
            string key = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                //Loop 34an agib kol 7rf fel key
                char a = 'a';
                for (; a <= 'z'; a++)
                {
                    char intersect = matrix[(plainText[i], a)];
                    if (cipherText[i] == intersect)
                    {
                        break;
                    }
                }
                key += a;
            }
            for (int i = 0; i < key.Length; i++)
            {
                string sub =  key.Substring(i, key.Length - i);
                if (plainText.Contains(sub)) {
                    string key2 = key.Remove(i);
                    if (Encrypt(plainText, key2) == cipherText) {
                        key = key2;
                        break;
                    }
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {

            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string plainText = "";
            Dictionary<(char, char), char> matrix = new Dictionary<(char, char), char>();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int v = (i + j) % 26;
                    matrix.Add(((char)(i + 97), (char)(j + 97)), (char)(v + 97));
                }
            }
            for (int i = 0; i < key.Length; i++)
            {
                char a = 'a';
                for (; a <= 'z'; a++) { 
                     char intersect = matrix[(key[i] ,a)];
                    if (cipherText[i] == intersect) {
                        break;
                    }
                }
                plainText += a;
            }

            if (key.Length < cipherText.Length)
            {
                int remainKey = cipherText.Length - key.Length;
                for (int i = 0; i < remainKey; i++)
                {

                    char KeyChar = plainText[i];
                    char a = 'a';
                    for (; a <= 'z'; a++)
                    {
                        char intersect = matrix[(KeyChar, a)];
                        if (cipherText[key.Length+i] == intersect)
                        {
                            break;
                        }
                    }
                    plainText += a;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            key = key.ToLower();
            string keystream="";
            if (key.Length < plainText.Length)
            {
                int remainKey = plainText.Length - key.Length;
                for (int i = 0; i < remainKey; i++)
                {
                    keystream += plainText[i];
                }
                key += keystream;
            }
            Dictionary<(char , char) , char> matrix = new Dictionary<(char, char), char>();
            for (int i = 0; i < 26; i++) {
                for (int j = 0; j < 26; j++) {
                    int v = (i + j) % 26;
                    matrix.Add(((char)(i+97), (char)(j+97)), (char)(v + 97));
                }
            }
            //Hna for loop (b3d m 5las b2a el key = plaintext)
            //34an nm4i 3la kol 7arf ngib el cipher bta3o
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                char intersect = matrix[(plainText[i], key[i])];
                cipher += intersect;
            }
            return cipher;
        }
    }
}
