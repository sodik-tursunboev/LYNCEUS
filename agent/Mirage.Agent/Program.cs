using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Mirage.Agent;

AgentConfig config;
try
{
    config = AgentConfig.Load(Path.Combine(AgentConfig.DefaultDataDir, "agent.json"));
}
catch (ConfigException e)
{
    Console.Error.WriteLine("MIRAGE agent: " + e.Message);
    return 2;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSingleton(config);
builder.Services.AddHostedService<AgentService>();
await builder.Build().RunAsync();
return 0;
