using JWTApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;

namespace JWTApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {


        // Set-Up API to require authorization

        // OnlyAdmins
        [HttpGet("Admins")]
        [Authorize(Roles = "Administrator")]
        public IActionResult AdminsEndPoint()
        {
            var user = GetCurrentUser();
            if(user != null)
            {
                return Ok($"Hi {user.GivenName} you're an {user.Role}");
            }
            return NotFound("User not found!");
        }

        // OnlySellers
        [HttpGet("Sellers")]
        [Authorize(Roles = "Seller")]
        public IActionResult SellersEndPoint()
        {
            var user = GetCurrentUser();
            if (user != null)
            {
                return Ok($"Hi {user.GivenName} you're a {user.Role}");
            }
            return NotFound("User not found!");
        }

        // Both Sellers and Admins
        [HttpGet("AdminsAndSellers")]
        [Authorize(Roles = "Administrator,Seller")]
        public IActionResult AdminsAndSellersEndPoint()
        {
            var user = GetCurrentUser();
            if (user != null)
            {
                return Ok($"Hi {user.GivenName} you're an {user.Role}");
            }
            return NotFound("User not found!");
        }



        [HttpGet("Public")]
        public IActionResult Public()
        {
            return Ok("You're on a public property.");
        }

        private UserModel GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var userClaims = identity.Claims;
                return new UserModel
                { 
                    Username = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier).Value,
                    EmailAddress = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Email).Value,
                    GivenName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.GivenName).Value,
                    Surname = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Surname).Value,
                    Role = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Role).Value
                };
            }
            return null;
        }
    }
}
