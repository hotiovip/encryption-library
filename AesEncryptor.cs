using System.Security.Cryptography;
using System.Text;

namespace Hotiovip.EncryptionLibrary
{
    public static class AesEncryptor
    {
        /// <summary>
        /// Encrypts a normal string using the AES Algorithm.
        /// </summary>
        /// <param name="textToEncrypt">String/Text to encrypt.</param>
        /// <param name="key">Secret Key to encrypt/decrypt the string.</param>
        /// <param name="IV">Initialization vector.</param>
        /// <returns>The encrypted text as a bytes array.</returns>
        public static string Encrypt(string text, string password, EncryptionMethod encryptionMethod)
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateIV();
                byte[] salt = GenerateSalt(16);
                aes.Key = GenerateSecretKey(password, salt, encryptionMethod);

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(Encoding.UTF8.GetBytes(text), 0, text.Length);
                    return Convert.ToBase64String(salt.Concat(aes.IV).Concat(encryptedBytes).ToArray());
                }
            }
        }
        /// <summary>
        /// Decrypts a normal string using the AES Algorithm.
        /// </summary>
        /// <param name="textToDecrypt">Byte array to decrypt.</param>
        /// <param name="key">Secret Key to encrypt/decrypt the string.</param>
        /// <param name="IV">Initialization vector.</param>
        /// <returns>The decrypted text as a string.</returns>
        public static string Decrypt(string text, string password, EncryptionMethod encryptionMethod)
        {
            try
            {
                byte[] byteText = Convert.FromBase64String(text);

                using (var aes = Aes.Create())
                {
                    // Extract salt and IV safely
                    byte[] salt = byteText.Take(16).ToArray();
                    byte[] iv = byteText.Skip(16).Take(16).ToArray();
                    byte[] encryptedText = byteText.Skip(32).ToArray();

                    aes.IV = iv;
                    aes.Key = GenerateSecretKey(password, salt, encryptionMethod);

                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedText, 0, encryptedText.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("The input string is not a valid Base64 string.", ex);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException("Decryption failed. Possibly due to wrong password, corrupted data, or mismatched encryption settings.", ex);
            }
            catch (Exception ex)
            {
                throw new Exception("An unexpected error occurred during decryption.", ex);
            }
        }

        /// <summary>
        /// Generates the secret key based on a given password.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <returns>Secret key as a byte array.</returns>
        private static byte[] GenerateSecretKey(string password, byte[] salt, EncryptionMethod encryptionMethod)
        {
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA512))
            {
                if (encryptionMethod.Equals(EncryptionMethod.AES256))
                {
                    return rfc2898DeriveBytes.GetBytes(32);
                }
                else
                {
                    return rfc2898DeriveBytes.GetBytes(16);
                }
            }
        }
        /// <summary>
        /// Generates a random salt (byte array) of the given size.
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        private static byte[] GenerateSalt(int size) => RandomNumberGenerator.GetBytes(size);
    }
}
