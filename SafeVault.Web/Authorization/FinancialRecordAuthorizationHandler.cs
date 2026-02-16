using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SafeVault.Web.Models;
using System.Security.Claims;

namespace SafeVault.Web.Authorization;

/// <summary>
/// Authorization handler for financial record operations
/// Ensures users can only access their own records unless they are Admin
/// </summary>
public class FinancialRecordAuthorizationHandler : 
    AuthorizationHandler<OperationAuthorizationRequirement, FinancialRecord>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        FinancialRecord resource)
    {
        if (context.User == null || resource == null)
        {
            return Task.CompletedTask;
        }

        // Admin can do anything
        if (context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Get the current user's ID
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        
        if (string.IsNullOrEmpty(userId))
        {
            return Task.CompletedTask;
        }

        // User can only access their own records
        if (resource.UserID == userId)
        {
            // Check if user has the required claim for the operation
            if (requirement.Name == Operations.Create.Name ||
                requirement.Name == Operations.Update.Name ||
                requirement.Name == Operations.Delete.Name)
            {
                // Check for CanManageFinancials claim
                if (context.User.HasClaim("CanManageFinancials", "true"))
                {
                    context.Succeed(requirement);
                }
            }
            else if (requirement.Name == Operations.Read.Name)
            {
                // All authenticated users can read their own records
                context.Succeed(requirement);
            }
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// Authorization handler for the FinancialRecordOwner requirement
/// </summary>
public class FinancialRecordOwnerAuthorizationHandler :
    AuthorizationHandler<FinancialRecordOwnerRequirement, FinancialRecord>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        FinancialRecordOwnerRequirement requirement,
        FinancialRecord resource)
    {
        if (context.User == null || resource == null)
        {
            return Task.CompletedTask;
        }

        // Admin can access any record
        if (context.User.IsInRole("Admin"))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Get the current user's ID
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        
        // User can only access their own records
        if (!string.IsNullOrEmpty(userId) && resource.UserID == userId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
