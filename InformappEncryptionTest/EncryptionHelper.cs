using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace InformappEncryptionTest
{
    public static class EncryptionHelper
    {
        /// <summary>
        /// Encrypt a string using a key
        /// </summary>
        /// <param name="toEncrypt">UTF-8 string to encrypt</param>
        /// <param name="key">Base64 string that represents the key</param>
        /// /// <param name="IV">Base64 string that represents the iv (not required)</param>
        /// <returns>encrypted version of your data</returns>
        public static string Encrypt(this string toEncrypt, string key, string IV = null)
        {
            byte[] keyBytes = KeyOrIVToBytes(key);
            byte[] ivBytes = KeyOrIVToBytes(IV);

            //encrypt and return
            try
            {
                byte[] encrypted = EncryptBytes(toEncrypt, keyBytes,ivBytes);

                return Convert.ToBase64String(encrypted);
            }
            catch (Exception e)
            {
                //failed to encrypt
                throw new Exception("There was an error encrypting your data", e);
            }
        }

        public static string Encrypt(this string toEncrypt, Tuple<string,string> keyiv)
        {
            return Encrypt(toEncrypt, keyiv.Item1, keyiv.Item2);
        }

        /// <summary>
        /// Decrypt a string using a key
        /// </summary>
        /// <param name="toDecrypt">data to decrypt</param>
        /// <param name="key">Base64 string that represents the key</param>
        /// <param name="IV">Bas64 string that represents the iv (not required)</param>
        /// <returns>decrypted version of the encrypted data</returns>
        public static string Decrypt(this string toDecrypt, string key, string IV = null)
        {
            byte[] keyBytes = KeyOrIVToBytes(key);
            byte[] ivBytes = KeyOrIVToBytes(IV);

            //decrypt and return
            try
            {
                byte[] decrypt = Convert.FromBase64String(toDecrypt);

                return DecryptBytes(decrypt, keyBytes, ivBytes);
            }
            catch (Exception e)
            {
                //failed to encrypt
                throw new Exception("There was an error decrypting your data", e);
            }
        }

        public static string Decrypt(this string toDecrypt, Tuple<string, string> keyiv)
        {
            return Decrypt(toDecrypt, keyiv.Item1, keyiv.Item2);
        }

        /// <summary>
        /// Generate an aes key and IV  (key,IV)
        /// </summary>
        public static Tuple<string,string> GenerateKeyAndIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                aes.GenerateKey();

                var IV = Convert.ToBase64String(aes.IV);
                var key = Convert.ToBase64String(aes.Key);
                return Tuple.Create(key, IV);
            }                
        }

        private static byte[] KeyOrIVToBytes(string key)
        {
            try
            {
                return Convert.FromBase64String(key);
            }
            catch (Exception e)
            {
                //not a base64 key
                throw new FormatException("key or iv string was not a properly formatted base64 string", e);
            }
        }

        private static byte[] EncryptBytes(string data, byte[] key, byte[] IV = null)
        {
            using (Aes aes = Aes.Create())
            {
                //set key
                aes.Key = key;
                if(IV != null) aes.IV = IV;

                //get encryptor
                ICryptoTransform cryptoTransform = aes.CreateEncryptor(aes.Key,aes.IV);
                byte[] encrypted;

                //encrypt
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(cryptoStream))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(data);
                        }
                        encrypted = memoryStream.ToArray();
                    }
                }
                return encrypted;
            }
        }

        private static string DecryptBytes(byte[] data, byte[] key, byte[] IV = null)
        {
            using (Aes aes = Aes.Create())
            {
                //set key
                aes.Key = key;
                if (IV != null) aes.IV = IV;

                //get decryptor
                ICryptoTransform cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
                string decryped;

                //decrypt
                using (MemoryStream memoryStream = new MemoryStream(data))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            decryped = streamReader.ReadToEnd();
                        }
                    }
                }
                return decryped;
            }
        }
    }
}
