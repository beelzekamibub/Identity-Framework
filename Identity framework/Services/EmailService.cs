using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using MailKit.Net.Smtp;
using Identity_framework.Interfaces;

namespace Identity_framework.Services
{
    public class EmailService: IEmailService
	{
		public async Task Send(string subject,string body,string to)
		{
			var email = new MimeMessage();
			email.From.Add(MailboxAddress.Parse("chait8126po@gmail.com"));
			email.To.Add(MailboxAddress.Parse(to));
			email.Subject = subject;
			email.Body = new TextPart(TextFormat.Plain) { Text = body };
			using var smtp = new SmtpClient();
			smtp.Connect("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
			string Password = Environment.GetEnvironmentVariable("POEMAILPASSWORD").ToString();
			smtp.Authenticate("chait8126po@gmail.com", Password);
			var response = await smtp.SendAsync(email);
			smtp.Disconnect(true);
		}
	}
}
