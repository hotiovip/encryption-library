using System.Security.Cryptography;
using System.Text;

namespace Hotiovip.EncryptionLibrary
{
    /// <summary>
    /// Static class for calling the various AES related methods.
    /// </summary>
    public static class AesEncryptor
    {
        /// <summary>
        /// Encrypts a normal string using the AES Algorithm.
        /// </summary>
        /// <param name="text">String/Text to encrypt</param>
        /// <param name="password">Password to encrypt the text with</param>
        /// <param name="encryptionMethod">Encryption method to encrypt with</param>
        /// <returns>The encrypted text as a string</returns>
        public static string Encrypt(string text, string password, EncryptionMethod encryptionMethod)
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateIV();
                byte[] salt = General.GenerateSalt(16);
                aes.Key = General.GenerateSecretKey(password, salt, encryptionMethod);

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
        /// <param name="text">String/Text to decrypt</param>
        /// <param name="password">Password to decrypt the text with</param>
        /// <param name="encryptionMethod">Encryption method to decrypt with</param>
        /// <returns>The decrypted text as a string</returns>
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
                    aes.Key = General.GenerateSecretKey(password, salt, encryptionMethod);

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
    }
}
