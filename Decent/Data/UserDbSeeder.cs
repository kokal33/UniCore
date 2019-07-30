using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Decent.Data;
using Decent.Models;

namespace Decent.Data
{
    public class UserDbSeeder
    {
        private readonly ILogger _logger;

        public UserDbSeeder(ILogger<UserDbSeeder> logger)
        {
            _logger = logger;
        }

        public async Task SeedAsync(IServiceProvider serviceProvider)
        {
            //Based on EF team's example at https://github.com/aspnet/MusicStore/blob/dev/samples/MusicStore/Models/SampleData.cs
            using (var serviceScope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = serviceScope.ServiceProvider.GetService<ApplicationDbContext>();
                context.Database.Migrate();

                if (await context.Database.EnsureCreatedAsync())
                {
                    if (!await context.Users.AnyAsync()) {await InsertUserData(context); }
                }
            }
        }

        public async Task InsertUserData(ApplicationDbContext db)
        {
            var users = GetUsers();
            db.Users.AddRange(users);

            try
            {
                await db.SaveChangesAsync();
            }
            catch (Exception exp)
            {
                _logger.LogError($"Error in {nameof(UserDbSeeder)}: " + exp.Message);
                throw;
            }

        }

        private List<User> GetUsers()
        {
            List<User> users = new List<User>();

            User admin = new User()
            {
                Email = "admin@admin.com",
                UserName = "Admin",
                EmailConfirmed = true,
                PasswordHash = "1234" //TODO: PASSWORD HASHER
            };
            users.Add(admin);
            return users;
        }
    }
}