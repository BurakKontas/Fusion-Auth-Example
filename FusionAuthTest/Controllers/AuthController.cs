using System.Linq.Expressions;
using FusionAuthTest.Contracts.EmailVerification;
using FusionAuthTest.Contracts.Family;
using FusionAuthTest.Contracts.HasRole;
using FusionAuthTest.Contracts.Register;
using io.fusionauth;
using io.fusionauth.domain;
using io.fusionauth.domain.api;
using io.fusionauth.domain.api.identityProvider;
using io.fusionauth.domain.api.jwt;
using io.fusionauth.domain.api.twoFactor;
using io.fusionauth.domain.api.user;
using io.fusionauth.domain.provider;
using Microsoft.AspNetCore.Mvc;

using ChangePasswordRequest = FusionAuthTest.Contracts.ChangePassword.ChangePasswordRequest;
using ForgotPasswordRequest = FusionAuthTest.Contracts.ForgotPassword.ForgotPasswordRequest;

using FusionLoginRequest = io.fusionauth.domain.api.LoginRequest;
using FusionForgotPasswordRequest = io.fusionauth.domain.api.user.ForgotPasswordRequest;
using FusionChangePasswordRequest = io.fusionauth.domain.api.user.ChangePasswordRequest;
using LoginRequest = FusionAuthTest.Contracts.Login.LoginRequest;
using LoginResponse = FusionAuthTest.Contracts.Login.LoginResponse;
using LogoutRequest = FusionAuthTest.Contracts.Logout.LogoutRequest;

namespace FusionAuthTest.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController(ILogger<AuthController> logger, FusionAuthSyncClient client)
        : ControllerBase
    {

        private readonly ILogger<AuthController> _logger = logger;
        private readonly Guid _applicationId = new("ac3c2bbc-45f6-4daf-bd55-86529b296faa");
        //private readonly Guid _applicationId = new("6cc9f1e3-7cc2-401c-86cd-ee6c74e60594");


        [HttpPost("/register")]
        public void Register([FromBody] RegisterRequest request)
        {
            var response = client.RetrieveUserByEmail(request.Email);

            if (response.WasSuccessful())
            {
                client.DeleteUser(response.successResponse.user.id);
            }

            var newUser = new User()
                .with(u => u.email = request.Email)
                .with(u => u.username = request.Username)
                .with(u => u.fullName = request.Fullname)
                .with(u => u.password = request.Password);

            var newRegistration = new UserRegistration()
                .with(r => r.applicationId = _applicationId)
                .with(r => r.username = request.Username);

            var registrationRequest = new RegistrationRequest()
                .with(rr => rr.user = newUser)
                .with(rr => rr.registration = newRegistration)
                .with(rr => rr.sendSetPasswordEmail = false)
                .with(rr => rr.skipVerification = false);

            var registerResponse = client.Register(null, registrationRequest);

            Console.WriteLine(registerResponse.successResponse.registrationVerificationId); // return this if you want to manually verify the email

            if (!registerResponse.WasSuccessful()) throw new Exception("User not created");

        }

        [HttpPost("/login")]
        public LoginResponse Login([FromBody] LoginRequest request)
        {
            var loginRequest = new FusionLoginRequest()
                .with(lr => lr.applicationId = _applicationId)
                .with(lr => lr.password = request.Password)
                .with(lr => lr.loginId = request.Email);

            var response = client.Login(loginRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
                
            return new LoginResponse(response.successResponse.token, response.successResponse.refreshToken);

        }

        [HttpPost("/logout")]
        public void Logout([FromBody] LogoutRequest request)
        {
            var response = client.Logout(false, request.RefreshToken);

            if (!response.WasSuccessful()) throw new BadHttpRequestException(response.exception.Message ?? "");
        }

        [HttpPost("/forgot-password")]
        public void ForgotPassword([FromBody] ForgotPasswordRequest request)
        {

            var forgotPasswordRequest = new FusionForgotPasswordRequest()
                .with(fp => fp.applicationId = _applicationId)
                .with(fp => fp.sendForgotPasswordEmail = true)
                .with(fp => fp.email = request.Email);

            var response = client.ForgotPassword(forgotPasswordRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }

        [HttpPost("/change-password")]
        public void ChangePassword([FromBody] ChangePasswordRequest request)
        {

            var changePasswordRequest = new FusionChangePasswordRequest()
                .with(cp => cp.applicationId = _applicationId)
                .with(cp => cp.currentPassword = request.CurrentPassword)
                .with(cp => cp.password = request.NewPassword)
                .with(cp => cp.loginId = request.Email);

            var response = client.ChangePasswordByIdentity(changePasswordRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }

        [HttpPost("/resend-email-verification")]
        public void VerifyEmail([FromBody] EmailVerificationRequest request)
        {
            var response = client.ResendEmailVerification(request.Email);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }

        [HttpPost("/has-role")]
        public bool HasRole([FromBody] HasRoleRequest request)
        {
            var response = client.RetrieveUserByEmail(request.Email);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
            
            var user = response.successResponse.user;

            var userRegistration = user.registrations.Find(r => r.applicationId == _applicationId);

            if (userRegistration == null) throw new ArgumentException("User not registered");

            return userRegistration.roles.Contains(request.Role);
        }

        [HttpPost("/validate-token")]
        public bool ValidateToken([FromBody] string token)
        {
            var response = client.ValidateJWT(token);

            return response.WasSuccessful();
        }

        [HttpPost("/refresh-token")]
        public LoginResponse RefreshToken([FromBody] string refreshToken)
        {

            var refreshTokenRequest = new RefreshRequest()
            {
                refreshToken = refreshToken
            };

            var response = client.ExchangeRefreshTokenForJWT(refreshTokenRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");

            return new LoginResponse(response.successResponse.token, response.successResponse.refreshToken);
        }

        //family add role delete etc.
        [HttpPost("/create-family")]
        public void CreateFamily([FromBody] CreateFamilyRequest request)
        {

            var user = client.RetrieveUserByEmail(request.Email);

            if(!user.WasSuccessful()) throw new ArgumentException(user.exception.Message ?? "");

            var familyMember = new FamilyMember()
                .with(fm => fm.role = FamilyRole.Adult)
                .with(fm => fm.owner = true)
                .with(fm => fm.userId = user.successResponse.user.id);

            var familyRequest = new FamilyRequest()
                .with(f => f.familyMember = familyMember);

            var response = client.CreateFamily(null, familyRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }

        [HttpPost("/add-family-member")]
        public void AddFamilyMember([FromBody] AddFamilyMemberRequest request)
        {
            var user = client.RetrieveUserByEmail(request.Email);

            if(!user.WasSuccessful()) throw new ArgumentException(user.exception.Message ?? "");


            var familyMember = new FamilyMember()
                .with(fm => fm.role = request.Role)
                .with(fm => fm.owner = request.IsOwner)
                .with(fm => fm.userId = user.successResponse.user.id);

            var familyRequest = new FamilyRequest()
                .with(f => f.familyMember = familyMember);

            var response = client.AddUserToFamily(request.FamilyId, familyRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }

        [HttpPost("/verify-registration")]
        public void VerifyEmail([FromBody] EmailVerifyRequest request)
        {
            var verificationRequest = new VerifyRegistrationRequest()
                .with(vr => vr.verificationId = request.VerificationId);

            var response = client.VerifyUserRegistration(verificationRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }

        [HttpPost("/verify-registration-with-code")]
        public void VerifyEmailWithCode([FromBody] EmailVerificationWithCodeRequest request)
        {
            var verificationRequest = new VerifyRegistrationRequest()
                .with(vr => vr.verificationId = request.VerificationId)
                .with(vr => vr.oneTimeCode = request.OneTimeCode);

            var response = client.VerifyUserRegistration(verificationRequest);

            if (!response.WasSuccessful()) throw new ArgumentException(response.exception.Message ?? "");
        }
    }
}

public record EmailVerifyRequest(string VerificationId);
public record EmailVerificationWithCodeRequest(string? OneTimeCode, string? VerificationId);