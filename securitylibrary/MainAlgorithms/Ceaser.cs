using System;
using System.Collections.Generic;
using System.Linq;


namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        Boolean revelio;
        char[] message;
        char[] letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        String encrypted_message = "";
        String decrypted_message = "";
        String recieved_message = "";
        int ensure_positivity = 26;

        public string Encrypt(string plainText, int key)
        {
            recieved_message = plainText.ToUpper();
            message = recieved_message.ToCharArray();

            int i = 0;
            for (; i < message.Length; i++)
            {
                int j = 0;
                for (; j < letters.Length; j++)
                {

                    revelio = message[i] == letters[j];
                    while (revelio)
                    {
                        encrypted_message +=
                            letters[(j + key) % 26].ToString();
                        break;
                    }

                    if (!revelio)

                        Console.WriteLine("Message is not encrypted yet");
                }
            }
            return encrypted_message;
        }

        public string Decrypt(string cipherText, int key)
        {
            recieved_message = cipherText;
            message = recieved_message.ToUpper().ToCharArray();
            decrypted_message = "";

            int i = 0;
            for (; i < message.Length; i++)
            {
                int j = 0;
                for (; j < letters.Length; j++)
                {
                    revelio = message[i] == letters[j];
                    while (revelio)
                    {
                        decrypted_message +=
                            letters[((j - key) % 26 + ensure_positivity) % 26].ToString();

                        break;
                    }

                    if (!revelio)

                        Console.WriteLine("Message is not decrypted yet");

                }
            }
            return decrypted_message;
        }


        public int Analyse(string plainText, string cipherText)
        {


            char first_in_cipher = Accio(cipherText, letters);
            char first_in_plain = Accio(plainText, letters);

            char Accio(string text, char[] list)
            {
                int counter = 0;
                revelio = counter < text.Length;
                while (revelio)
                {
                    char small_letter = text[counter];
                    char capital_letter = char.ToUpper(small_letter);
                    char matching = (capital_letter >= 'A' && capital_letter <= 'Z') ? capital_letter : '\0';

                    if (matching != '\0')
                    {
                        return matching;
                    }

                    else
                    {
                        Console.WriteLine("Operation failed");
                    }

                    counter++;
                }

                return '\0';
            }


            //DETECTING SHIFTS 

            if (plainText.Length != cipherText.Length)

                return -1;


            int diff = (first_in_cipher - first_in_plain);
            int positions_shifted = diff;

            revelio = positions_shifted < 0;
            int shift_final_value = revelio ? (positions_shifted + ensure_positivity)
                : (positions_shifted % 26);

            return shift_final_value; ;

        }
    }
}