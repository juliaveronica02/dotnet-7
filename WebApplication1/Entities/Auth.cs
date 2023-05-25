using System;
using System.Collections.Generic;

namespace WebApplication1.Entities;

public partial class Auth
{
    public int Id { get; set; }

    public string Username { get; set; } = null!;

    public string Email { get; set; } = null!;

    public long Phone { get; set; }

    public string Password { get; set; } = null!; // swagger testing password: noName!1.

	public DateTime CreatedAt { get; set; }

    public DateTime UpdatedAt { get; set; }
}
