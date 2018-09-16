using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using PersonalPhotos.Interfaces;

namespace PersonalPhotos.Strategies
{
    public class SmtpEmail : IEmail
    {
        private readonly EmailOptions _options;

        public SmtpEmail(IOptions<EmailOptions> options)
        {
            _options = options.Value;
        }
        public async Task Send(string emailAddress, string body)
        {
            var client = new SmtpClient {Host = _options.Host, Port = _options.Port, Credentials = new NetworkCredential(_options.UserName, _options.Password)};

            var message = new MailMessage("enter from email address here", emailAddress)
            {
                Body = body,
                IsBodyHtml = true
            };

            await client.SendMailAsync(message);
        }
    }
}
