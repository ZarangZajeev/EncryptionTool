using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EncryptionTool
{
    public partial class Form1 : Form
    {
        private readonly byte[] _key;
        public Form1()
        {
            InitializeComponent();

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            string key = ConfigurationManager.AppSettings["EncryptionKey"];
            txtOutput.Text = Encrypt(txtInput.Text, key);
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            string key = ConfigurationManager.AppSettings["EncryptionKey"];
            txtOutput.Text = Decrypt(txtInput.Text, key);
        }

        public static byte[] GetKey(string key)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(key)); // 32 bytes
            }
        }

        public static string Encrypt(string plainText, string key)
        {
            byte[] keyBytes = GetKey(key);
            byte[] ivBytes = new byte[16];

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = ivBytes;

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        public static string Decrypt(string encryptedText, string key)
        {
            byte[] keyBytes = GetKey(key);
            byte[] ivBytes = new byte[16];

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = ivBytes;

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] encryptedBytes = Convert.FromBase64String(encryptedText);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }

    }
}
