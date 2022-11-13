using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Pomelo.Security.Ssl
{
    public class OpenSSL
    {
        private readonly string openSslPath;
        private readonly string workingDirectory;

        public OpenSSL(string openSslPath)
        {
            this.openSslPath = openSslPath;
            this.workingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            InitDirectories();
        }

        private void InitDirectories()
        {
            var ssldbPath = Path.Combine(workingDirectory, "ssldb");
            if (!Directory.Exists(ssldbPath))
            {
                Directory.CreateDirectory(ssldbPath);
                File.WriteAllText(Path.Combine(ssldbPath, "crlnumber"), "01");
                File.WriteAllText(Path.Combine(ssldbPath, "index.txt"), "");
                File.WriteAllText(Path.Combine(ssldbPath, "serial"), "01");
            }
        }

        public void GenerateRsaPrivateKey(string outFile, string password)
        {
            var args = $"genrsa -aes128 -passout pass:{password} -out \"{outFile}\" 2048";
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    WorkingDirectory = workingDirectory
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
            string keyFile,
            string keyPassword,
            string countryCode = "CN",
            string province = "Shanghai",
            string city = "Shanghai",
            string organization = "Pomelo Foundation",
            string organizationUnit = "Pomelo Foundation Open Source Department",
            string commonName = "Pomelo Foundation Root CA",
            string email = "noreply@pomelo.cloud")
        {
            var cnfContent = File.ReadAllText(Path.Combine("Template", "template_intermediate.cnf"))
                .Replace("{COUNTRY}", countryCode)
                .Replace("{PROVINCE}", province)
                .Replace("{CITY}", city)
                .Replace("{ORGANIZATION}", organization)
                .Replace("{ORGANIZATION_UNIT}", organizationUnit)
                .Replace("{COMMON_NAME}", commonName)
                .Replace("{EMAIL_ADDR}", email);

            var cnfFile = Path.ChangeExtension(outFile, ".cnf");
            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }
            File.WriteAllText(cnfFile, cnfContent);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"req -new -key \"{keyFile}\" -passin pass:{keyPassword} -out \"{outFile}\" -config \"{cnfFile}\"",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.WaitForExit();
            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void GenerateMultiDomainCsr(
            string outFile,
            string keyFile,
            string keyPassword,
            string countryCode = "CN",
            string province = "Shanghai",
            string city = "Shanghai",
            string organization = "Pomelo Foundation",
            string organizationUnit = "Pomelo Foundation Open Source Department",
            string commonName = "Pomelo Foundation Root CA",
            string email = "noreply@pomelo.cloud")
        {
            var cnfContent = File.ReadAllText(Path.Combine("Template", "template_intermediate.cnf"))
                .Replace("{COUNTRY}", countryCode)
                .Replace("{PROVINCE}", province)
                .Replace("{CITY}", city)
                .Replace("{ORGANIZATION}", organization)
                .Replace("{ORGANIZATION_UNIT}", organizationUnit)
                .Replace("{COMMON_NAME}", commonName)
                .Replace("{EMAIL_ADDR}", email);

            var cnfFile = Path.ChangeExtension(outFile, ".cnf");
            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }
            File.WriteAllText(cnfFile, cnfContent);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"req -new -key \"{keyFile}\" -passin pass:{keyPassword} -out \"{outFile}\" -config \"{cnfFile}\"",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.WaitForExit();
            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void GenerateSelfSignedCert(string csrFile, string keyFile, string outFile, int days, string keyPassword, string algorithm = "sha256")
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"x509 -req -{algorithm} -in \"{csrFile}\" -signkey \"{keyFile}\" -out \"{outFile}\" -days {days} -passin pass:{keyPassword}",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void ConvertCrtAndKeyToPfx(string crtFile, string keyFile, string outFile, string keyPassword, string pfxPassword)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"pkcs12 -export -in {crtFile} -inkey {keyFile} -out {outFile} -passin pass:{keyPassword} -passout pass:{pfxPassword}",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void SignIntermediateCaCert(
            string csrFile,
            string outFile,
            int days,
            string caCrtFile,
            string caKeyFile,
            string caKeyPassword,
            string algorithm = "sha256",
            string[] crlUrls = null)
        {
            var crlSection = new StringBuilder();
            if (crlUrls != null && crlUrls.Length > 0)
            {
                crlSection.Append($"crlDistributionPoints = {string.Join(",", crlUrls.Select(x => "URI:" + x))}");
            }

            var cnfFile = Guid.NewGuid() + ".cnf";
            var cnfContent = File.ReadAllText(Path.Combine("Template", "template_ca.cnf"));
            cnfContent = cnfContent.Replace("{CRL_URLS}", crlSection.ToString());
            File.WriteAllText(cnfFile, cnfContent);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"ca -config {cnfFile} -cert \"{caCrtFile}\" -keyfile \"{caKeyFile}\" -passin pass:{caKeyPassword} -days {days} -md {algorithm} -in {csrFile} -out \"{Path.GetFileName(outFile)}\" -outdir ./",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.StandardInput.WriteLine("y");
            process.StandardInput.WriteLine("y");
            process.StandardInput.Close();
            process.WaitForExit();

            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void SignServerCert(
            string csrFile,
            string outFile,
            int days,
            string caCrtFile,
            string caKeyFile,
            string caKeyPassword,
            string algorithm = "sha256",
            string[] dns = null,
            string[] crlUrls = null)
        {
            var dnsSection = new StringBuilder();
            if (dns != null && dns.Length > 0)
            {
                dnsSection.Append($"subjectAltName = {string.Join(",", dns.Select(x => "DNS:" + x))}");
            }

            var crlSection = new StringBuilder();
            if (crlUrls != null && crlUrls.Length > 0)
            {
                crlSection.Append($"crlDistributionPoints = {string.Join(",", crlUrls.Select(x => "URI:" + x))}");
            }

            var cnfFile = Guid.NewGuid() + ".cnf";
            var cnfContent = File.ReadAllText(Path.Combine("Template", "template_server.cnf"));
            cnfContent = cnfContent
                .Replace("{CRL_URLS}", crlSection.ToString())
                .Replace("{DNS}", dnsSection.ToString());
            File.WriteAllText(cnfFile, cnfContent);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"ca -config {cnfFile} -cert \"{caCrtFile}\" -keyfile \"{caKeyFile}\" -passin pass:{caKeyPassword} -days {days} -md {algorithm} -in {csrFile} -out \"{Path.GetFileName(outFile)}\" -outdir ./",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.StandardInput.WriteLine("y");
            process.StandardInput.WriteLine("y");
            process.StandardInput.Close();
            process.WaitForExit();

            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void SignClientCert(
            string csrFile,
            string outFile,
            int days,
            string caCrtFile,
            string caKeyFile,
            string caKeyPassword,
            string algorithm = "sha256",
            string[] crlUrls = null)
        {
            var crlSection = new StringBuilder();
            if (crlUrls != null && crlUrls.Length > 0)
            {
                crlSection.Append($"crlDistributionPoints = {string.Join(",", crlUrls.Select(x => "URI:" + x))}");
            }

            var cnfFile = Guid.NewGuid() + ".cnf";
            var cnfContent = File.ReadAllText(Path.Combine("Template", "template_client.cnf"));
            cnfContent = cnfContent
                .Replace("{CRL_URLS}", crlSection.ToString());
            File.WriteAllText(cnfFile, cnfContent);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"ca -config {cnfFile} -cert \"{caCrtFile}\" -keyfile \"{caKeyFile}\" -passin pass:{caKeyPassword} -days {days} -md {algorithm} -in {csrFile} -out \"{Path.GetFileName(outFile)}\" -outdir ./",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.StandardInput.WriteLine("y");
            process.StandardInput.WriteLine("y");
            process.StandardInput.Close();
            process.WaitForExit();

            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public void SignCodeSigningCert(
            string csrFile,
            string outFile,
            int days,
            string caCrtFile,
            string caKeyFile,
            string caKeyPassword,
            string algorithm = "sha256",
            string[] crlUrls = null)
        {
            var crlSection = new StringBuilder();
            if (crlUrls != null && crlUrls.Length > 0)
            {
                crlSection.Append($"crlDistributionPoints = {string.Join(",", crlUrls.Select(x => "URI:" + x))}");
            }

            var cnfFile = Guid.NewGuid() + ".cnf";
            var cnfContent = File.ReadAllText(Path.Combine("Template", "template_codesign.cnf"));
            cnfContent = cnfContent
                .Replace("{CRL_URLS}", crlSection.ToString());
            File.WriteAllText(cnfFile, cnfContent);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"ca -config {cnfFile} -cert \"{caCrtFile}\" -keyfile \"{caKeyFile}\" -passin pass:{caKeyPassword} -days {days} -md {algorithm} -in {csrFile} -out \"{Path.GetFileName(outFile)}\" -outdir ./",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.StandardInput.WriteLine("y");
            process.StandardInput.WriteLine("y");
            process.StandardInput.Close();
            process.WaitForExit();

            if (File.Exists(cnfFile))
            {
                File.Delete(cnfFile);
            }

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }
        }

        public string GetCommonNameFromCsr(string csrFile)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = openSslPath,
                    Arguments = $"req -text -noout -verify -in \"{csrFile}\"",
                    UseShellExecute = false,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    WorkingDirectory = workingDirectory
                }
            };

            process.Start();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
            }

            var result = process.StandardOutput.ReadToEnd();
            var splited = result.Split('\n').Where(x => x.Contains("Subject:") && x.Contains("ST = ") && x.Contains("CN = ")).ToList();
            if (splited.Count == 0)
            {
                return null;
            }

            var text = splited.First().Split(',').SingleOrDefault(x => x.Contains("CN = "));
            if (text == null)
            {
                return null;
            }

            return text.Substring("CN = ".Length).Trim();
        }
    }
}
