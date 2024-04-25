namespace FusionAuthTest.Contracts.ChangePassword;

public record ChangePasswordRequest(string Email, string CurrentPassword, string NewPassword);