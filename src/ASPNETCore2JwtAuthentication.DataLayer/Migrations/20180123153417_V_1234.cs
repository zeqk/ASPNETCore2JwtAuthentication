using Microsoft.EntityFrameworkCore.Migrations;
using System;
using System.Collections.Generic;

namespace ASPNETCore2JwtAuthentication.DataLayer.Migrations
{
    public partial class V_1234 : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AccessTokenExpiresDateTime",
                table: "UserTokens");

            migrationBuilder.DropColumn(
                name: "AccessTokenHash",
                table: "UserTokens");

            migrationBuilder.AddColumn<string>(
                name: "RefreshTokenSerial",
                table: "UserTokens",
                type: "nvarchar(max)",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RefreshTokenSerial",
                table: "UserTokens");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "AccessTokenExpiresDateTime",
                table: "UserTokens",
                nullable: false,
                defaultValue: new DateTimeOffset(new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)));

            migrationBuilder.AddColumn<string>(
                name: "AccessTokenHash",
                table: "UserTokens",
                nullable: true);
        }
    }
}
