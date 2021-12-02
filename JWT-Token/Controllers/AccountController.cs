using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using JWT_Token.Models;
using Microsoft.IdentityModel.Tokens;

namespace JWT_Token.Controllers
{
    public class AccountController : Controller
    {
        // тестовые данные для входа
        private List<User> _users = new List<User>
        {
            new User {Login="admin@gmail.com", Password="12345", Role = "admin" },
            new User { Login="user@gmail.com", Password="55555", Role = "user" }
        };

        //обработка запроса, принимает логин и пароль
        [HttpPost("/token")]
        public IActionResult Token(string username, string password)
        {
            //получить идентификатор пользователя
            var identity = GetIdentity(username, password);
            if (identity == null)
            {
                return BadRequest(new { errorText = "Не правильный Логин или Email" });
            }

            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var jwt = new JwtSecurityToken(
                issuer: AuthOpt.ISSUER,
                audience: AuthOpt.AUDIENCE,
                notBefore: now,

                claims: identity.Claims,
                expires: now.Add(TimeSpan.FromMinutes(AuthOpt.LIFETIME)),
                signingCredentials: new SigningCredentials(AuthOpt.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            //токен
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
            //ответ
            var response = new
            {
                access_token = encodedJwt,
                username = identity.Name
            };
            return Json(response);
        }//Token

        //ищем пользователя в нашем списке разрешенных пользователей
        private ClaimsIdentity GetIdentity(string username, string password)
        {
            User person = _users.FirstOrDefault(x => x.Login == username && x.Password == password);
            if (person != null)
            {
                //для авторизации
                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, person.Login),
                    new Claim(ClaimsIdentity.DefaultRoleClaimType, person.Role)
                };
                //идентификатор пользователя
                ClaimsIdentity claimsIdentity =
                    new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }

            // если пользователя не найдено
            return null;
        }//GetIdentity
    }
}
