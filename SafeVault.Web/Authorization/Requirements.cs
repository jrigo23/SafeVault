using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace SafeVault.Web.Authorization;

/// <summary>
/// Custom authorization requirements for SafeVault
/// </summary>
public static class Operations
{
    public static OperationAuthorizationRequirement Create = 
        new() { Name = nameof(Create) };
    
    public static OperationAuthorizationRequirement Read = 
        new() { Name = nameof(Read) };
    
    public static OperationAuthorizationRequirement Update = 
        new() { Name = nameof(Update) };
    
    public static OperationAuthorizationRequirement Delete = 
        new() { Name = nameof(Delete) };
}

/// <summary>
/// Custom requirement for financial record ownership
/// </summary>
public class FinancialRecordOwnerRequirement : IAuthorizationRequirement
{
}
