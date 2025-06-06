using System.Security.Cryptography;
using System.Text;

namespace Hotiovip.EncryptionLibrary
{
    /// <summary>
    /// Class containing method to help create and compare hashes.
    /// </summary>
    public class HashHelper
    {
        /// <summary>
        /// Gets the hash of the given string as a string.
        /// </summary>
        /// <param name="inputString">The input string to get the hash of</param>
        /// <returns>the hash as a string</returns>
        private static string GetHashString(string inputString)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
            {
                byte[] hash = algorithm.ComputeHash(Encoding.UTF8.GetBytes(inputString));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }

        /// <summary>
        /// Generates the hash for the given string and the salt it appended to the string before the hash.
        /// </summary>
        /// <param name="inputString">String to hash</param>
        /// <param name="saltSize">Length of the salt. 16 is a good one</param>
        /// <param name="salt">(Optional) Salt to append before the string. Is only needed when trying to compare hashes</param>
        /// <returns>The salted hash and the salt added before hashing</returns>
        public static (string saltedHash, string salt) GenerateHash(string inputString, string? salt = null, int saltSize = 16)
        {
            if (salt == null) salt = General.GenerateStringSalt(saltSize);
            string saltedHash = GetHashString(salt + inputString);

            return (saltedHash, salt);
        }
        /// <summary>
        /// Compares a normal string with a hashes string. Needs the salt used before hashing to generate the same string (if obviously the input string is the same)
        /// </summary>
        /// <param name="inputString">String to hash and compare</param>
        /// <param name="hashString">Hashed string</param>
        /// <param name="salt">Salt appended to the hashed string before hashing</param>
        /// <returns>True if the two hashes are the same, else otherwise</returns>
        public static bool CompareStringWithHash(string inputString, string hashString, string salt)
        {
            string saltedHashedInputString = GenerateHash(inputString, salt).saltedHash;
            byte[] hashBytesA = Encoding.UTF8.GetBytes(saltedHashedInputString);
            byte[] hashBytesB = Encoding.UTF8.GetBytes(hashString);

            // Using this to avoid "time attacks"
            return CryptographicOperations.FixedTimeEquals(hashBytesA, hashBytesB);
        }
    }
}
