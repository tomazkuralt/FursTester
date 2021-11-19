using Agitavit.FormNet.Infrastructure.Integrations;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace FursTester
{
    class Program
    {
        static IConfiguration config;
        static void Main(string[] args)
        {
            try
            {
                var builder = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false);

                 config = builder.Build();

                FursService service = new FursService(config);
                service.ExecuteCall();
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
}
