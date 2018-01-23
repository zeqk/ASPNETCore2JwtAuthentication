using System;

namespace ASPNETCore2JwtAuthentication.DomainClasses
{
    public class UserToken
    {
        public int Id { get; set; }

        public string RefreshTokenSerial { get; set; }

        public string RefreshTokenIdHash { get; set; }

        public DateTimeOffset RefreshTokenExpiresDateTime { get; set; }

        public int UserId { get; set; }
        public virtual User User { get; set; }
    }
}