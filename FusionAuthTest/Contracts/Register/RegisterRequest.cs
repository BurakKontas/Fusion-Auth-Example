namespace FusionAuthTest.Contracts.Register;

public record RegisterRequest(string Email, string Username, string Fullname, string Password);