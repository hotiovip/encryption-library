using System.Data;
using System.Security.Cryptography;

namespace Hotiovip.EncryptionLibrary
{
    /// <summary>
    /// General class for methods to use in the whole project.
    /// </summary>
    internal class General
    {
        /// <summary>
        /// Generates the secret key based on a given password.
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="salt">Salt</param>
        /// <param name="encryptionMethod">Encryption method to generate the secret key with</param>
        /// <returns>Secret key as a byte array</returns>
        internal static byte[] GenerateSecretKey(string password, byte[] salt, EncryptionMethod encryptionMethod)
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
        /// Generates a random salt (bytes array) of the given size.
        /// </summary>
        /// <param name="size"></param>
        /// <returns>The salt as a bytes array</returns>
        internal static byte[] GenerateSalt(int size) => RandomNumberGenerator.GetBytes(size);
        internal static string GenerateStringSalt(int size)
        {
            byte[] byteSalt = GenerateSalt(size);
            return Convert.ToBase64String(byteSalt);
        }
    }
}
