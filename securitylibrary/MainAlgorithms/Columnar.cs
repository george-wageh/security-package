using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class Columnar : ICryptographicTechnique<string, List<int>>
    {


        public int Accio_rows(string cipherText, int depth, int columns, List<int> key)
        {
            bool revelio1 = (cipherText.Length % key.Count) == 0;
            bool revelio2 = (cipherText.Length % columns) != 0;
            int rows;

            if (revelio1)
            {
                rows = cipherText.Length / depth;
            }
            else
            {
                rows = cipherText.Length / columns;

                if (revelio2)
                {
                    rows++;
                }
            }

            return rows;
        }


        Boolean revelio;


        string Accio_texts(char[,] matrix, int x, int y)
        {
            if (matrix[x, y] != null)
            {
                return matrix[x, y].ToString();
            }
            else
            {
                throw new Exception(" There is no element :( ");
            }
        }

        int k = 0;

        public List<int> Analyse(string plainText, string cipherText)
        {

            cipherText = cipherText.ToLower();
            int columns = 0;

            int maxima = 2;
            for (; maxima < 8; maxima++)
            {
                revelio = plainText.Length % maxima == 0;

                if (revelio)
                    columns = maxima;
            }

            List<int> key = new List<int>(columns);
            int depth = key.Count;
            Boolean We_succeeded = depth == 0;

            int rows = (plainText.Length / columns);
            int final_number_of_cols = columns + 2;

            char[,] plain_matrix = new char[rows, columns];
            char[,] cipher_matrix = new char[rows, columns];


            int maxima1 = 0;
            int r1 = 0;
            for (; r1 < rows; r1++)
                for (int c1 = 0; c1 < columns && maxima1 < plainText.Length; c1++, maxima1++)
                    plain_matrix[r1, c1] = plainText[maxima1];

            int maxima2 = 0;
            int c2 = 0;
            for (; c2 < columns; c2++)
                for (int r2 = 0; r2 < rows && maxima2 < plainText.Length; r2++, maxima2++)
                    cipher_matrix[r2, c2] = cipherText[maxima2];



            int column_i = 0;
            while (column_i < columns)
            {
                int key_i = 0;
                while (key_i < columns)
                {
                    int snap = 0;
                    int row_i = 0;
                    while (row_i < rows)
                    {
                        if (plain_matrix[row_i, column_i] == cipher_matrix[row_i, key_i])
                            snap++;
                        row_i++;
                    }
                    if (snap == rows)
                        key.Add(key_i + 1);
                    key_i++;
                }
                column_i++;
            }

            if (We_succeeded)
            {
                for (; k < final_number_of_cols; k++)
                    key.Add(7);
            }

            return key;
        }


        public string Decrypt(string cipherText, List<int> key)
        {

            int depth = key.Count;
            int columns = depth;

            int rows = Accio_rows(cipherText, depth, columns, key);

            char[,] matrix = new char[rows, columns];

            int free_columns = (rows * columns) - cipherText.Length;
            int maxima = 0;
            int max = 1;

            int column = 0;
            for (; column < columns; column++)
            {
                int index = key.IndexOf(max);
                max++;

                for (int row = 0; row < rows; row++)
                {
                    Boolean Lastrow_aw_Enoughspace = row != rows - 1 || (column + 1) + free_columns <= columns;

                    if (Lastrow_aw_Enoughspace)
                    {
                        matrix[row, index] = cipherText[maxima];
                        maxima++;
                    }
                }
            }



            string plain_text = "";

            int x = 0;
            for (; x < rows; x++)
            {
                int y = 0;
                for (; y < columns; y++)
                {

                    plain_text += Accio_texts(matrix, x, y);

                }
            }
            return plain_text;

        }



        public string Encrypt(string plainText, List<int> key)
        {

            int depth = key.Count;
            int columns = depth;

            int rows = Accio_rows(plainText, depth, columns, key);

            Char[,] matrix = new char[rows, columns];

            int maxima = 0;
            int i = 0;
            for (; i < rows; i++)
            {
                int j = 0;
                for (; j < columns && maxima < plainText.Length; j++)
                {
                    matrix[i, j] = plainText[maxima];
                    maxima++;
                }
            }


            String cipher_text = "";

            int x = 1;
            for (; x <= columns; x++)
            {
                int index = key.IndexOf(x);

                int y = 0;
                for (; y < rows; y++)
                {

                    cipher_text += Accio_texts(matrix, y, index);

                }
            }

            return cipher_text;
        }
    }

}
