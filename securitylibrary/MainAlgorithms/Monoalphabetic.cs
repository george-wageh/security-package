using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        readonly char[] alphabet = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        Boolean revelio;
        char[] key = new char[26];
        public string Analyse(string plainText, string cipherText)
        {
            char[] key = new char[26];
            var empty_spaces = Enumerable.Repeat(' ', 26);
            key = empty_spaces.ToArray();
            Dictionary<char, char> mapping = new Dictionary<char, char>();
            //Mapping cipher with plain
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int m = 0;
            for (; m < plainText.Length; m++)
            {
                bool revelio = mapping.ContainsKey(plainText[m]);

                if (!revelio)
                {
                    try
                    {
                        mapping.Add(plainText[m], cipherText[m]);
                    }
                    catch
                    {
                        Console.WriteLine(" Mapping faced an error #_# ");
                    }
                }

                else
                {
                    continue;
                }
            }
            // Now hncreate key array 
            int k = 0;
            for (; k < key.Length; k++)
            {
                revelio = mapping.TryGetValue(alphabet[k], out char cipher_character);
                if (revelio)
                    try
                    {
                        key[k] = cipher_character;
                    }
                    catch
                    {
                        Console.WriteLine(" Array creation crashed ");
                    }

                else
                {
                    key[k] = ' ';
                }
            }
            // Characters in 'alphabet' msh mwgoda fy el 'key'
            var characters_remaining = alphabet.Except(key);

            var characters_remaining_array = characters_remaining.ToArray();

            var characters_remained = new string(characters_remaining_array);
            int index = 0;
            int counter = 0;
            String final_key = "";
            for (; counter < key.Length; counter++)
            {
                revelio = key[counter] == ' ';
                if (revelio)
                    try
                    {
                        key[counter] = characters_remained[index];
                        index++;
                    }
                    catch
                    {
                        Console.WriteLine("We did not return the whole key");
                    }

            }

            final_key = new string(key);
            return final_key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();

            Dictionary<char, char> letters = new Dictionary<char, char>();
            int k = 0;
            string plainText = "";
            cipherText = cipherText.ToLower();
            for (char i = 'a'; i <= 'z'; i++)
            {
                letters.Add(key[k], i);
                k++;

            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText += letters[cipherText[i]];
            }

            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            Dictionary<char, char> letters = new Dictionary<char, char>();
            int k = 0;
            string cipherText = "";
            for (char i = 'a'; i <= 'z'; i++)
            {
                letters.Add(i, key[k]);
                k++;

            }
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += letters[plainText[i]];
            }

            return cipherText;

        }







        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {

            //throw new NotImplementedException();
            cipher = cipher.ToLower();
            string plainText = "";
            char[] sortedFrequencies = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            int c = 0;
            Dictionary<char, int> letters = new Dictionary<char, int>();
            Dictionary<char, char> plain = new Dictionary<char, char>();
            for (int i = 0; i < cipher.Length; i++)
            {
                if (letters.ContainsKey(cipher[i]))
                {
                    letters[cipher[i]]++;
                }
                else
                {
                    letters.Add(cipher[i], 1);
                }

            }
            var sortedVlues = letters.OrderByDescending(value => value.Value).ToDictionary(value => value.Key, value => value.Value);
            for (int i = 0; i < sortedFrequencies.Length; i++)
            {
                if (!(sortedVlues.ContainsKey(sortedFrequencies[i])))
                {
                    sortedVlues.Add(sortedFrequencies[i], 0);
                }
            }
            foreach (var item in sortedVlues.Keys)
            {
                plain.Add(item, sortedFrequencies[c]);
                c++;
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                plainText += plain[cipher[i]];
            }
            return plainText;
        }
    }
}