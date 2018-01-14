using System.IO;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Sso
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddEnvironmentVariables()
                .AddCommandLine(args)
                .Build();

            var host = WebHost.CreateDefaultBuilder(args)
                              .UseConfiguration(config)
                              .UseStartup<Startup>()
                              .UseUrls("http://*:5000")
                              .Build();

            host.Run();
        }
    }
}
