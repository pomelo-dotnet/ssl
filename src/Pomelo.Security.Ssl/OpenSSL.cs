using System;
using System.Diagnostics;

namespace Pomelo.Security.Ssl
{
    public class OpenSSL
    {
        private readonly string openSslPath;
        public OpenSSL(string openSslPath)
        {
            this.openSslPath = openSslPath;
        }

        public void GenerateRsaPrivateKey(string outFile, string password)
        {
            using var process = new Process 
            {
                StartInfo = new ProcessStartInfo 
                {
                    FileName = openSslPath,
                    Arguments = $"genrsa -aes128 -passout pass:{password} -out \"{outFile}\" 2048",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true
                }
            };

            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void GenerateCsr(
            string outFile,
            string privateKeyFile,
            string privateKeyPassword,
            string countryCode = "CN", 
            string province = "Shanghai", 
            string city = "Shanghai",
            string organization = "Pomelo Foundation",
            string section = "Open Source Department",
            string commonName = "Pomelo Foundation Root CA",
            int days = 7300,
            string challengePassword = "",
            string companyName = "")
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"req -new -key {privateKeyFile} -passin pass:{privateKeyPassword} -out \"{outFile}\" -days {days}",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true
                }
            };

            process.Start();
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(countryCode);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(province);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(city);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(organization);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(section);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(commonName);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(challengePassword);
            process.WaitForInputIdle();
            process.StandardInput.WriteLine(companyName);
            process.StandardInput.Close();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }
    }
}
