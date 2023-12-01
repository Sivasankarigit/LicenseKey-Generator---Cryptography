using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualBasic;
using Microsoft.Win32;
using System.Management;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Reflection.PortableExecutable;

namespace LicenseGeneratorFinal.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LicenseController : ControllerBase
    {

        private readonly IConfiguration _configuration;

        public LicenseController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpGet]
        [Route("LincenseValidity")]
        public string Getlincense(string lnumUser, string idType)
        {
            
            StringBuilder sb = new StringBuilder();
            sb.Append(lnumUser);
            sb.Append("|");

            switch (idType.ToLower())
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
            string EncryptValue;
            string EncrptSalt;
            EncrptSalt = "A1B2C3D4E5F6G7H8";
            string currentTime = DateTime.Now.ToString("MM-dd-yyyy HH:mm:ss");
            EncryptValue = Encrypt(currentTime, EncrptSalt);
            string filePath = _configuration["LincenseKeyFile:LincenseKey"];

            if (string.IsNullOrEmpty(filePath))
            {
                throw new Exception("OutputFilePath is not specified in appsettings.json");
            }

            // Write values to the specified text file
            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine($"{hashValues},{EncryptValue}");

                return EncryptValue;
            }

        }


        //For Encrypt Date

        private string Encrypt(string inputText, string EncryptionKey)
        {

            byte[] clearBytes = Encoding.Unicode.GetBytes(inputText);


            using (Aes encryptor = Aes.Create())
            {

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });


                encryptor.Key = pdb.GetBytes(32);  // 256-bit key
                encryptor.IV = pdb.GetBytes(16);   // 128-bit IV


                using (MemoryStream ms = new MemoryStream())
                {

                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    inputText = Convert.ToBase64String(ms.ToArray());
                }
            }

            return inputText;
        }



        // Sha Algorithm

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
    }
}
