using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

public class Program
{
    public static void Main(string[] args)
    {
        Console.Write("Enter a password to save hash: ");
        string password = Console.ReadLine();

        var result = HashPassword(password, null, false);

        Console.Write("\nEnter a password to check hash: ");
        password = Console.ReadLine();

        bool checkResult = CheckPassword(result, password);
        Console.ForegroundColor = checkResult ? ConsoleColor.Green : ConsoleColor.Red;
        Console.WriteLine("\nPassword " + (checkResult ? "correct" : "incorrect"));
        Console.ResetColor();

        Console.WriteLine("\n\nReferences: https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing?view=aspnetcore-5.0");
    }

    private static string HashPassword(string password, byte[] salt = null, bool needsOnlyHash = false)
    {
        if (salt == null)
        {
            // generate a 256-bit salt
            salt = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetNonZeroBytes(salt);
            }
        }

        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: password,
            salt: salt, // used to allow multiple users with same password
            prf: KeyDerivationPrf.HMACSHA256, //pseudo-random function to use
            iterationCount: 100000,
            numBytesRequested: 32 //length requested
            ));

        var passwordAndHash = $"{hashed}:{Convert.ToBase64String(salt)}";
        Console.WriteLine($"Hash generated:\n{passwordAndHash}");

        if (needsOnlyHash) return hashed;

        // password will be concatenated with salt using ':'
        return passwordAndHash;
    }

    private static bool CheckPassword(string hashedPasswordWithSalt, string passwordToCheck)
    {
        // retrieve salt and password
        var passwordAndHash = hashedPasswordWithSalt.Split(':');

        //convert base64 string to byte array
        var salt = Convert.FromBase64String(passwordAndHash[1]);

        if (salt == null) return false;

        // hash the given password
        var hashOfpasswordToCheck = HashPassword(passwordToCheck, salt, true);

        // compare both hashes
        return String.Compare(passwordAndHash[0], hashOfpasswordToCheck) == 0;
    }
}

