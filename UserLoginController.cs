using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Management;
using System.Text;
using System;

namespace UserLogin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserLoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public UserLoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpGet]
        [Route("User")]
        public string UserLogin(string username, string password, String idType,string numberofUser)
        {
            string id = idType;
            string numofUser = numberofUser;

            string filePath = _configuration["LincenseKeyFile:LincenseKey"];

            string firstValue = "";
            string SecondValue = "";


            string DecryptValue = "";

            DateTime datetime;
            DateTime dateTime;



            // FilePath (Check)

            if (string.IsNullOrEmpty(filePath))
            {
                throw new Exception("FilePath is not specified in appsettings.json");
            }

            // From file Encrypted LicenceKey Value Read

            using (StreamReader reader = new StreamReader(filePath))
            {
                while(!reader.EndOfStream)
                {
                    string line = reader.ReadLine();

                    string[] values = line.Split(',');

                    if (values.Length >= 1)
                    {
                        firstValue = values[0].Trim();
                        SecondValue = values[1].Trim();

             

                    }




                }
            }

         

            // Method Call

            string LicenseValue = Getlincense(numofUser,id);

            //return SecondValue;


            string EncrptSalt;
            EncrptSalt = "A1B2C3D4E5F6G7H8";
            DecryptValue = Decrypt(SecondValue, EncrptSalt);

           // return DecryptValue;

          
            string expireDate = "12-12-2022 12:00:00";

            dateTime = DateTime.Parse(DecryptValue);
            datetime = DateTime.Parse(expireDate);



            // Condition Check

            if (firstValue.Equals(LicenseValue))
            {
                if (dateTime <= datetime)
                {
                    string userName = username;
                    string passWord = password;
                    return "License Valid";

                }

                else
                {
                    return "License Will Be Expired";
                }
            }


            else
            {
                throw new Exception("You Cant Login in this system");

            }
        }


        // License Generotor Decision Makeing

        private string Getlincense(string lnumUser, string idType)
        {
            string idValue = idType;
            idValue = idValue.ToLower();
            StringBuilder sb = new StringBuilder();

            sb.Append(lnumUser);
            sb.Append("|");

            switch (idValue)
            {
                case "machineid":
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                    object information = (key.GetValue("MachineGuid"));
                    sb.Append(information);
                    break;

                case "uuid":
                    using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
                    {
                        ManagementObjectCollection managementObjects = searcher.Get();

                        foreach (var managementObject in managementObjects)
                        {
                            object uuidObject = managementObject["UUID"];

                            if (uuidObject != null)
                            {
                                sb.Append(uuidObject);
                            }
                        }
                    }
                    break;

                default:
                    throw new Exception("Invalid Id");

            }

            string value = sb.ToString();

            var hashValues = ValueEncryption(value);
            return hashValues;


        }

        // Sha Algorithm - Licemse Key Generator
        private string ValueEncryption(string variable)
        {
            byte[] salt = new byte[16];
            salt = Encoding.UTF8.GetBytes("A1B2C3D4E5F6G7H8");

            {
                using (SHA256 sha256 = SHA256.Create())
                {

                    byte[] hashvalue = Encoding.UTF8.GetBytes(variable).Concat(salt).ToArray();
                    byte[] hashBytes = sha256.ComputeHash(hashvalue);
                    string str1 = BitConverter.ToString(hashBytes).Replace("-", "");
                    return str1;

                }


            }

        }


        // Encrypt Date ---> Decrypt (Value Retrive)

        private string Decrypt(string cipherText, string EncryptionKey)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

                encryptor.Key = pdb.GetBytes(32);  // 256-bit key
                encryptor.IV = pdb.GetBytes(16);   // 128-bit IV

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
           
                }
            }
            return cipherText;
        }







    }
}

