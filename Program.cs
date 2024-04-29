using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Orleans.Configuration;
using Orleans.Hosting;
using Orleans.Serialization;
using ProofService.interfaces;
using ZkProof.Grains;

public class Program
{
    static async Task Main(string[] args)
    {
        try
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
            var configuration = builder.Build();

            var siloPort = 11111;
            var gatewayPort = 30000;
            var host = new HostBuilder()
                .UseOrleans((ctx, siloBuilder) => siloBuilder
                    .UseLocalhostClustering()
                    .ConfigureEndpoints(siloPort, gatewayPort)
                    .ConfigureServices(services =>
                    {
                        services.Configure<ZkProverSetting>(configuration.GetSection("ProverSetting"));
                        services.Configure<ContractClient>(configuration.GetSection("ContractClient"));
                        services.AddSerializer(serializerBuilder =>
                        {
                            serializerBuilder.AddNewtonsoftJsonSerializer(
                                    isSupported: type => type.Namespace.StartsWith("Grains"))
                                .AddNewtonsoftJsonSerializer(
                                    isSupported: type => type.Namespace.StartsWith("Controllers"));
                        });
                    })
                    .Configure<ClientMessagingOptions>(opts =>
                    {
                        opts.ResponseTimeout = TimeSpan.FromMinutes(30);
                    })
                    .Configure<SiloMessagingOptions>(opts =>
                    {
                        opts.ResponseTimeout = TimeSpan.FromMinutes(30);
                    })
                )
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                })
                .ConfigureLogging(logging => logging.AddConsole(options =>
                {
                    options.IncludeScopes = true;
                    options.TimestampFormat = "yyyy-MM-dd hh:mm:ss";
                }))
                .Build();

            await host.StartAsync();

            await Task.Delay(-1);
        }
        catch (Exception ex)
        {
            Console.WriteLine("start fail, e: " + ex.Message);
        }
    }
}