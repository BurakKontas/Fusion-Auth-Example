using io.fusionauth.domain;

namespace FusionAuthTest.Contracts.Family;

public record AddFamilyMemberRequest(Guid FamilyId, string Email, FamilyRole Role, bool IsOwner = false);