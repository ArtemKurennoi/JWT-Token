using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace JWT_Token.Models
{
    public class AuthOpt
    {
        // издатель токена
        public const string ISSUER = "MyAuthServer";
        // потребитель токена
        public const string AUDIENCE = "MyAuthClient";
        // ключ для шифрации
        const string KEY = "mysupersecret_secretkey!123";
        // время жизни токена - 1 минута
        public const int LIFETIME = 1; 
        public static SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(KEY));
        }
    }
}
