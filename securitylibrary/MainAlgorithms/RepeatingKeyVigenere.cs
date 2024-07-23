using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public string Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
                throw new ArgumentException("Plaintext and ciphertext must be of the same length.");

            StringBuilder the_key_Builder = new StringBuilder();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsLetter(plainText[i]) && char.IsLetter(cipherText[i]))
                {
                    int Shift = (char.ToUpper(cipherText[i]) - char.ToUpper(plainText[i]) + 26) % 26;
                    char key_Charactar = (char)('A' + Shift);
                    the_key_Builder.Append(key_Charactar);
                }
            }

            string the_whole_Key = the_key_Builder.ToString();
            return Extract_Smallest_RepeatingPattern(the_whole_Key);
        }

        private string Extract_Smallest_RepeatingPattern(string key)
        {
            for (int the_pattern_Length = 1; the_pattern_Length <= key.Length / 2; the_pattern_Length++)
            {
                bool mismatch_Found = false;
                string pattern = key.Substring(0, the_pattern_Length);

                for (int the_offset = the_pattern_Length; the_offset <= key.Length - the_pattern_Length; the_offset += the_pattern_Length)
                {
                    if (!key.Substring(the_offset, the_pattern_Length).Equals(pattern))
                    {
                        mismatch_Found = true;
                        break;
                    }
                }

                if (!mismatch_Found)
                {
                    return pattern;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string Resultant_M = "";
            int key_Index = 0;
            int Cipher_Text_Lengh = cipherText.Length;
            int key_Lengh = key.Length;

            for (int i = 0; i < Cipher_Text_Lengh; i++)
            {
                char carac = cipherText[i];
                if (!char.IsLetter(carac))
                {
                    // ben3ml append lel non-alphabetic characters to the result
                    Resultant_M += carac;
                    continue;
                }
                bool Is_Upper_Case = char.IsUpper(carac);
                int char_Position = char.ToUpper(carac) - 'A';
                int key_Char_Position = char.ToUpper(key[key_Index % key_Lengh]) - 'A';
                // ben3ml decrypt lel charactar 
                int Decrypted_Char_Position = (char_Position - key_Char_Position + 26) % 26;
                char Decrypted_Char = (char)(Decrypted_Char_Position + (Is_Upper_Case ? 'A' : 'a'));

                Resultant_M += Decrypted_Char;
                key_Index++;
            }

            return Resultant_M;
        }
        public string Encrypt(string plainText, string key)
        {
            StringBuilder resultant_m = new StringBuilder();
            for (int i = 0, j = 0; i < plainText.Length; i++)
            {
                char carac = plainText[i];
                if (char.IsLetter(carac))
                {
                    bool IsUpper_Case = char.IsUpper(carac);
                    char The_Offset = IsUpper_Case ? 'A' : 'a';
                    carac = (char)((carac + key[j % key.Length] - 2 * The_Offset) % 26 + The_Offset);
                    j++;
                }
                resultant_m.Append(carac);
            }
            return resultant_m.ToString();
        }
    }
}

