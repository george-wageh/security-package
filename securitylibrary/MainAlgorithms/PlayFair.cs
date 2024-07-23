using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        (char[,] , Dictionary<char, (int, int)>) buildMatrix(string key) {
            key = key.ToLower().Replace(" ", "");
            key = key.Replace('j', 'i');
            char[,] matrix = new char[5, 5];
            Dictionary<char, (int, int)> dictionary = new Dictionary<char, (int, int)>();
            int i = 0, j = 0;
            foreach (char c in key)
            {
                if (!dictionary.ContainsKey(c))
                {
                    if (j % 5 == 0 && j != 0)
                    {
                        j = 0;
                        i++;
                    }
                    matrix[i, j] = c;
                    dictionary.Add(c, (i, j));
                    j++;
                }
            }
            for (char a = 'a'; a <= 'z'; a++)
            {
                if (a == 'j')
                    continue;
                if (!dictionary.ContainsKey(a))
                {
                    if (j % 5 == 0 && j != 0)
                    {
                        j = 0;
                        i++;
                    }
                    matrix[i, j] = a;
                    dictionary.Add(a, (i, j));
                    j++;
                }
            }
            return (matrix , dictionary);
        }
        public string Decrypt(string cipherText, string key)
        {
            var (matrix, dictionary) = buildMatrix(key);
            cipherText = cipherText.ToLower().Replace(" ", "");
            cipherText = cipherText.Replace("j", "i");
            List<(char, char)> cipherList = new List<(char, char)>();
            for (int index = 0; index < cipherText.Length; index+=2)
            {
                cipherList.Add((cipherText[index], cipherText[index + 1]));
            }
            string plainText = "";
            var (prvA, preB) = ('a', 'a');
            foreach (var(a, b) in  cipherList)
            {
                var (i1, j1) = dictionary[a];
                var (i2, j2) = dictionary[b];

                var x = ('a', 'a');
                if (i1 == i2)
                {
                    x.Item1 = matrix[i1, (((j1 - 1) % 5) + 5) % 5];
                    x.Item2 = matrix[i2, (((j2 - 1) % 5) + 5) % 5];
                }
                else if (j1 == j2)
                {
                    x.Item1 = matrix[(((i1 - 1) % 5) + 5) % 5 , j1];
                    x.Item2 = matrix[(((i2 - 1) % 5) + 5) % 5 , j2];
                }
                else
                {
                    x.Item1 = matrix[i1, j2];
                    x.Item2 = matrix[i2, j1];
                }

                if (prvA != x.Item1 && preB == 'x') {
                    plainText += 'x';
                }

                if (x.Item2 == 'x')
                {
                    plainText += x.Item1;
                }
                else {
                    plainText = plainText + x.Item1 + x.Item2;
                }
                (prvA, preB) = x;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            var (matrix, dictionary) = buildMatrix(key);

            plainText = plainText.ToLower().Replace(" ", "");
            plainText = plainText.Replace("j", "i");
           
            List<(char , char)> diagramList = new List<(char , char)>();

            for (int index = 0; index < plainText.Length; index++) {
                if (index == plainText.Length - 1) {
                    diagramList.Add((plainText[index], 'x'));
                }
                else if((plainText[index] == plainText[index + 1]) ) {
                    diagramList.Add((plainText[index], 'x'));
                }
                else {
                    diagramList.Add((plainText[index], plainText[index + 1]));
                    index++;
                }
            }
            string cipherText = "";
            foreach ((char a, char b) in diagramList) {
                var (i1, j1) = dictionary[a];
                var (i2, j2) = dictionary[b];

                var x = ('a', 'a');
                if (i1 == i2)
                {
                    x.Item1 = matrix[i1, (j1 + 1) % 5];
                    x.Item2 = matrix[i2, (j2 + 1) % 5];
                }
                else if (j1 == j2) {
                    x.Item1 = matrix[(i1 + 1) % 5, j1];
                    x.Item2 = matrix[(i2 + 1) % 5, j2];
                }
                else
                {
                    x.Item1 = matrix[i1, j2];
                    x.Item2 = matrix[i2, j1];
                }
                cipherText = cipherText + x.Item1 + x.Item2;
            }

            return cipherText;

        }
    }
}