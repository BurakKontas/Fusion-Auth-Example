using io.fusionauth;
using System;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHttpClient();

var client = new FusionAuthSyncClient("L3iSgPrg3VpyXUTZq6lR9nEVhHK2NvNvN8XoVSgm5th1Q7tQilHwF7Z7", "http://localhost:9011");
//var client = new FusionAuthSyncClient("LE0CRUaA4oadkI8zuqx3oN9utJO1l6f3AH8Jfs-_JIYP5Dt_VFabftcD", "https://auth.colyakdiyabet.com.tr");

builder.Services.AddSingleton(client);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
