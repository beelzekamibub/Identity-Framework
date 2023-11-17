namespace Identity_framework.Interfaces
{
    public interface IEmailService
    {
        public Task Send(string subject,string body, string to);
    }
}
